import os
import re
import asyncio
import subprocess
import logging
import sqlite3
from datetime import datetime

import nmap_pars
import cve_update as cveup
import data_managment as data
import report 

from aiogram import Bot, Dispatcher, types, F
from aiogram.fsm import state
from aiogram.fsm.state import StatesGroup, State
from aiogram.fsm.context import FSMContext
from aiogram.filters import Command
from aiogram.types import CallbackQuery, FSInputFile
from aiogram.utils.keyboard import InlineKeyboardBuilder

port_list = [20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 119, 123, 143, 161, 162, 179, 389, 443, 465, 993, 995]
API_TOKEN = '7871599954:AAFz9rXh4PNr0_2B6WqyBYkBPyE7reMMigs'
TARGET_DIRECTORY = '/home/kali/Desktop/CSU/CVEScannerV2/'
LOG_FILE = 'logfile.log'

logging.basicConfig(level=logging.INFO)

bot = Bot(token=API_TOKEN)
dp = Dispatcher()

class Form(StatesGroup):
    waiting_for_target = State()


@dp.message(Command("start"))
async def cmd_start(message: types.Message):
    keyboard = InlineKeyboardBuilder()
    keyboard.button(text="🔍 Запустить сканер", callback_data="start_scan")
    await message.answer(
        "👋 Приветствую! Этот бот предназначен для мониторинга серверов на наличие уязвимостей.\n\n"
        "📌 Доступные команды:\n"
        "• /info — показать информацию о вашем сервере и результатах последнего сканирования.\n\n"
        "📥 Чтобы начать, нажмите кнопку ниже или введите домен/IP вручную.\n\n"
        "⚠️ Пожалуйста, указывайте адрес сервера **в правильном формате**:\n"
        "• Доменное имя: `example.com`\n"
        "• Или IP-адрес: `192.168.1.1`\n\n",
        reply_markup=keyboard.as_markup()
    )

@dp.message(Command("info"))
async def info_command(message: types.Message):
    user_id = message.from_user.id
    with sqlite3.connect("server.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT S.domain, MAX(Sc.scan_time)
            FROM Users U
            JOIN Servers S ON S.user_id = U.id
            JOIN Scans Sc ON Sc.server_id = S.id
            WHERE U.tg_user = ?
        """, (user_id,))
        row = cursor.fetchone()

    if row and row[0]:
        domain, last_scan = row
        scan_time = datetime.fromisoformat(last_scan)
        formatted_time = scan_time.strftime('%d.%m.%Y %H:%M')
        last_scan = last_scan or "Нет данных"
        text = f"🌐 Сервер: {domain}\n🕓 Последнее сканирование: {formatted_time}"
        keyboard = InlineKeyboardBuilder()
        keyboard.button(text="🗑 Удалить сервер", callback_data="delete_server")
        keyboard.button(text="✏ Изменить сервер", callback_data="change_server")
        await message.answer(text, reply_markup=keyboard.as_markup())
    else:
        await message.answer("Вы ещё не добавили сервер.")

@dp.callback_query(F.data == "start_scan")
async def scan_callback(callback: CallbackQuery, state: FSMContext):
    from_user_id = callback.from_user.id
    with sqlite3.connect("server.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT S.domain
            FROM Users U
            JOIN Servers S ON S.user_id = U.id
            WHERE U.tg_user = ?
        """, (from_user_id,))
        row = cursor.fetchone()

    if row:
        domain = row[0]
        await callback.message.answer(f"Найден зарегистрированный сервер: {domain}\nЗапускаю сканирование...")
        await callback.answer()
        await run_scan_update(callback.message, domain, from_user_id)
    else:
        await state.update_data(user_id=from_user_id)
        await callback.message.answer("Введите IP-адрес или домен сервера для сканирования.")
        await state.set_state(Form.waiting_for_target)
        await callback.answer()

async def delete_user_data(user_id: int) -> bool:
    with sqlite3.connect("server.db") as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM Users WHERE tg_user = ?", (user_id,))
        row = cursor.fetchone()
        if not row:
            return False

        user_db_id = row[0]

        cursor.execute("DELETE FROM CVEs WHERE software_id IN (SELECT id FROM Software WHERE scan_id IN (SELECT id FROM Scans WHERE server_id = (SELECT id FROM Servers WHERE user_id = ?)))", (user_db_id,))
        cursor.execute("DELETE FROM Software WHERE scan_id IN (SELECT id FROM Scans WHERE server_id = (SELECT id FROM Servers WHERE user_id = ?))", (user_db_id,))
        cursor.execute("DELETE FROM Scans WHERE server_id = (SELECT id FROM Servers WHERE user_id = ?)", (user_db_id,))
        cursor.execute("DELETE FROM Servers WHERE user_id = ?", (user_db_id,))
        cursor.execute("DELETE FROM ScanSchedule WHERE user_id = ?", (user_db_id,))
        conn.commit()
    return True


@dp.message(Command("reset"))
async def reset_server(message: types.Message):
    user_id = message.from_user.id
    success = await delete_user_data(user_id)

    if success:
        await message.reply("✅ Сервер и связанные данные успешно удалены. При следующем сканировании вы сможете ввести новый сервер.")
    else:
        await message.reply("ℹ Вы ещё не зарегистрированы в системе.")


@dp.callback_query(F.data == "delete_server")
async def delete_server(callback: CallbackQuery):
    user_id = callback.from_user.id
    success = await delete_user_data(user_id)

    if success:
        await callback.message.answer("🗑 Сервер и все данные удалены.")
    else:
        await callback.message.answer("ℹ Вы ещё не зарегистрированы в системе.")
    await callback.answer()


@dp.callback_query(F.data == "change_server")
async def change_server(callback: CallbackQuery, state: FSMContext):
    user_id = callback.from_user.id
    success = await delete_user_data(user_id)

    if success:
        await callback.message.answer("✏ Сервер удалён. Введите новый IP-адрес или домен для сканирования:")
        await state.update_data(user_id=user_id)
        await state.set_state(Form.waiting_for_target)
    else:
        await callback.message.answer("ℹ Вы ещё не зарегистрированы в системе.")
    await callback.answer()

@dp.message(Form.waiting_for_target)
async def process_target(message: types.Message, state: FSMContext):
    user_input = message.text.strip()
    data_state = await state.get_data()
    user_id = data_state.get("user_id")

    target = re.split(r"[ ,]", user_input)[0]

    valid = re.match(
        r"^(?:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3})$",
        target
    )
    if not valid:
        await message.reply("❌ Введите корректный домен или IP-адрес. Пример: `example.com` или `192.168.1.1`")
        return

    with sqlite3.connect("server.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM Servers WHERE domain = ?", (target,))
        row = cursor.fetchone()
        if row:
            if row[0] != user_id:
                await message.reply("❌ Такой сервер уже зарегистрирован другим пользователем. Введите другой.")
                return
            else:
                await message.reply("ℹ️ Этот сервер уже зарегистрирован вами.")
                return

    await message.reply(f"🚀 Запускаю сканирование {target}...")
    await state.clear()
    await run_scan(message, target, user_id)


async def run_scan(message: types.Message, target: str, user_id: int):
    os.chdir(TARGET_DIRECTORY)
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)

    try:
        for port in port_list:
            command = f"nmap -sV --script ~/Desktop/CSU/CVEScannerV2/cvescannerv2.nse --script-args log={LOG_FILE} -p {port} {target}"
            subprocess.run(command, shell=True, check=True)

            results = nmap_pars.parse_log_file(LOG_FILE)
            if results:
                with open(LOG_FILE, "r") as f:
                    content = f.read().strip()
                    if content.startswith("##") and len(content.splitlines()) == 1:
                        data.save_scan_data_manual(user_id=user_id, domain=target, port=port)
                        os.remove(LOG_FILE)
                        continue
                data.save_scan_data(LOG_FILE, user_id, target)
            else:
                data.save_scan_data_manual(user_id=user_id, domain=target, port=port)

            if os.path.exists(LOG_FILE):
                os.remove(LOG_FILE)

        file_path = report.export_user_scan_results_pdf(user_id)
        document = FSInputFile(file_path)
        await message.reply_document(document, caption="📄 Сканирование завершено. Вот ваш PDF-отчёт.")
        os.remove(file_path)
    except Exception as e:
        await message.reply(f"❌ Произошла ошибка при сканировании: {e}")


async def run_scan_update(message: types.Message, target: str, user_id: int):
    os.chdir(TARGET_DIRECTORY)
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)

    try:
        for port in port_list:
            command = f"nmap -sV --script ~/Desktop/CSU/CVEScannerV2/cvescannerv2.nse --script-args log={LOG_FILE} -p {port} {target}"
            subprocess.run(command, shell=True, check=True)

            results = nmap_pars.parse_log_file(LOG_FILE)
            if results:
                with open(LOG_FILE, "r") as f:
                    content = f.read().strip()
                    if content.startswith("##") and len(content.splitlines()) == 1:
                        data.update_scan_data_no_vuln(user_id=user_id, domain=target, port=port)
                        os.remove(LOG_FILE)
                        continue
                    else:
                        data.save_scan_data_if_new(LOG_FILE, user_id=user_id, domain=target)

            else:
                data.save_scan_data_manual(user_id=user_id, domain=target, port=port)

            if os.path.exists(LOG_FILE):
                os.remove(LOG_FILE)

        file_path = report.export_user_scan_results_pdf(user_id)
        document = FSInputFile(file_path)
        await message.reply_document(document, caption="📄 Повторное сканирование завершено. PDF-отчёт:")
        os.remove(file_path)
    except Exception as e:
        await message.reply(f"❌ Ошибка при повторном сканировании: {e}")


async def check_and_run_scheduled_scans():
    now = datetime.now()
    with sqlite3.connect("server.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT U.tg_user, S.domain, MAX(Sc.scan_time)
            FROM Users U
            JOIN Servers S ON S.user_id = U.id
            LEFT JOIN Scans Sc ON Sc.server_id = S.id
            GROUP BY S.id
        """)
        rows = cursor.fetchall()

    for tg_user, domain, last_scan in rows:
        if last_scan:
            last_scan_time = datetime.fromisoformat(last_scan)
            if (now - last_scan_time).days < 3:
                continue
        try:
            user_id = tg_user
            fake_message = types.Message(
                message_id=0,
                date=now,
                chat=types.Chat(id=user_id, type="private"),
                from_user=types.User(id=user_id, is_bot=False, first_name="User"),
                message_thread_id=None,
                text=f"⏱ Автосканирование {domain}"
            )
            await run_scan_update(fake_message, domain, user_id)
        except Exception as e:
            print(f"Ошибка при автосканировании {domain}: {e}")



async def periodic_scan():
    while True:
        await asyncio.sleep(1800)
        await check_and_run_scheduled_scans()

async def main():
    data.check_db()
    asyncio.create_task(periodic_scan())
    await dp.start_polling(bot)

if __name__ == '__main__':
    asyncio.run(main())