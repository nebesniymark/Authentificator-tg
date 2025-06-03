from aiogram import Bot, Dispatcher, types, executor
from mnemonic import Mnemonic
import hmac, hashlib, base64, time, os

API_TOKEN = os.getenv("API_TOKEN")
bot = Bot(token=API_TOKEN)
dp = Dispatcher(bot)

def generate_totp(secret: bytes, time_step=30, digits=6):
    counter = int(time.time()) // time_step
    key = base64.b32decode(secret, casefold=True)
    msg = counter.to_bytes(8, 'big')
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = (int.from_bytes(h[o:o+4], 'big') & 0x7fffffff) % (10 ** digits)
    return str(code).zfill(digits)

def derive_secret(seed: str, label: str):
    seed_bytes = hashlib.sha256((seed + label).encode()).digest()
    return base64.b32encode(seed_bytes[:20]).decode()

@dp.message_handler(commands=['start'])
async def start(msg: types.Message):
    await msg.answer("Привет! Введи seed-фразу или напиши /gen для генерации новой.")

@dp.message_handler(commands=['gen'])
async def gen(msg: types.Message):
    m = Mnemonic("english")
    phrase = m.generate(strength=128)
    await msg.answer(f"Seed:\n`{phrase}`", parse_mode="Markdown")

@dp.message_handler(lambda m: len(m.text.split()) >= 12)
async def seed_input(msg: types.Message):
    seed = msg.text.strip()
    await msg.answer("Теперь введи название сервиса (например, `gmail`, `github`).")

    @dp.message_handler()
    async def label_input(m: types.Message):
        label = m.text.strip()
        secret = derive_secret(seed, label)
        code = generate_totp(secret)
        await m.answer(f"TOTP код для `{label}`:\n`{code}`", parse_mode="Markdown")

if __name__ == '__main__':
    executor.start_polling(dp, skip_updates=True)
