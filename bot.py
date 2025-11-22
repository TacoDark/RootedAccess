import discord
from discord import app_commands
from discord.ext import commands
import os
from dotenv import load_dotenv
import aiohttp
import random
import base64
import hashlib
import string
import time
import uuid
import datetime
import asyncio
import json
import urllib.parse
import ipaddress
import re
from typing import Literal, Optional

# Load environment variables
load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

# Setup intents
intents = discord.Intents.default()
intents.message_content = True
intents.members = True

class RootedBot(commands.Bot):
    def __init__(self):
        super().__init__(command_prefix='!', intents=intents)

    async def setup_hook(self):
        await self.tree.sync()
        print("Synced command tree")

bot = RootedBot()
start_time = time.time()

@bot.event
async def on_ready():
    print(f'{bot.user} has connected to Discord!')
    await bot.change_presence(activity=discord.Game(name="/help | Rooted Access"))

@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    print(f"[ERROR] Command: {interaction.command.name if interaction.command else 'Unknown'} | Error: {error}")
    if not interaction.response.is_done():
        await interaction.response.send_message(f"An error occurred: {str(error)}", ephemeral=True)
    else:
        await interaction.followup.send(f"An error occurred: {str(error)}", ephemeral=True)

# --- Logging ---

@bot.event
async def on_app_command_completion(interaction: discord.Interaction, command: app_commands.Command):
    print(f"[LOG] User: {interaction.user} (ID: {interaction.user.id}) | Command: /{command.name} | Channel: {interaction.channel} | Time: {datetime.datetime.now()}")

# --- Security & Dev Commands ---

@bot.tree.command(name="scan_code", description="Static analysis for dangerous Python patterns")
async def scan_code(interaction: discord.Interaction, code: str):
    dangerous_patterns = [
        r"eval\(", r"exec\(", r"os\.system", r"subprocess\.call", 
        r"subprocess\.Popen", r"import os", r"import sys", r"__import__",
        r"open\(", r"requests\.get", r"urllib\.request"
    ]
    found = []
    for pattern in dangerous_patterns:
        if re.search(pattern, code):
            found.append(pattern.replace('\\', ''))
    
    if found:
        await interaction.response.send_message(f"⚠️ **Potential Security Risks Found:**\n`{', '.join(found)}`", ephemeral=True)
    else:
        await interaction.response.send_message("✅ No obvious dangerous patterns found (basic scan).", ephemeral=True)

@bot.tree.command(name="expand_url", description="Unshortens redirects to show the final destination")
async def expand_url(interaction: discord.Interaction, url: str):
    if not url.startswith("http"):
        url = "http://" + url
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.head(url, allow_redirects=True) as resp:
                await interaction.response.send_message(f"Original: <{url}>\nFinal: <{resp.url}>")
    except Exception as e:
        await interaction.response.send_message(f"Error expanding URL: {str(e)}", ephemeral=True)

@bot.tree.command(name="pass_strength", description="Estimates password strength")
async def pass_strength(interaction: discord.Interaction, password: str):
    length_score = min(len(password) / 12, 1.0) * 40
    variety_score = 0
    if re.search(r"[a-z]", password): variety_score += 15
    if re.search(r"[A-Z]", password): variety_score += 15
    if re.search(r"\d", password): variety_score += 15
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): variety_score += 15
    
    total_score = min(length_score + variety_score, 100)
    
    rating = "Weak"
    color = discord.Color.red()
    if total_score > 60:
        rating = "Medium"
        color = discord.Color.gold()
    if total_score > 80:
        rating = "Strong"
        color = discord.Color.green()
        
    embed = discord.Embed(title="Password Strength", color=color)
    embed.add_field(name="Rating", value=rating)
    embed.add_field(name="Score", value=f"{int(total_score)}/100")
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="chmod", description="Converts permissions (e.g. 777 <-> rwxrwxrwx)")
async def chmod(interaction: discord.Interaction, value: str):
    # Numeric to Symbolic
    if value.isdigit() and len(value) == 3:
        mapping = {
            '0': '---', '1': '--x', '2': '-w-', '3': '-wx',
            '4': 'r--', '5': 'r-x', '6': 'rw-', '7': 'rwx'
        }
        res = "".join(mapping.get(c, '???') for c in value)
        await interaction.response.send_message(f"chmod {value} = `{res}`")
    # Symbolic to Numeric (basic implementation)
    elif len(value) == 9:
        # rwxrwxrwx
        try:
            user = value[0:3]
            group = value[3:6]
            other = value[6:9]
            
            def to_num(perm):
                n = 0
                if 'r' in perm: n += 4
                if 'w' in perm: n += 2
                if 'x' in perm: n += 1
                return str(n)
            
            res = to_num(user) + to_num(group) + to_num(other)
            await interaction.response.send_message(f"chmod {value} = `{res}`")
        except:
            await interaction.response.send_message("Invalid format. Use 777 or rwxrwxrwx.")
    else:
        await interaction.response.send_message("Invalid format. Use 3 digits (777) or 9 chars (rwxrwxrwx).")

@bot.tree.command(name="cidr", description="Calculates IP range for a CIDR block")
async def cidr(interaction: discord.Interaction, network: str):
    try:
        net = ipaddress.ip_network(network, strict=False)
        embed = discord.Embed(title=f"CIDR: {network}", color=discord.Color.blue())
        embed.add_field(name="Num Addresses", value=str(net.num_addresses), inline=True)
        embed.add_field(name="Netmask", value=str(net.netmask), inline=True)
        embed.add_field(name="First IP", value=str(net[0]), inline=True)
        embed.add_field(name="Last IP", value=str(net[-1]), inline=True)
        await interaction.response.send_message(embed=embed)
    except ValueError:
        await interaction.response.send_message("Invalid CIDR notation.", ephemeral=True)

@bot.tree.command(name="dns", description="Resolves A and AAAA records for a domain")
async def dns(interaction: discord.Interaction, domain: str):
    try:
        loop = asyncio.get_running_loop()
        # Run blocking socket calls in executor
        a_records = await loop.run_in_executor(None, socket.gethostbyname_ex, domain)
        
        embed = discord.Embed(title=f"DNS: {domain}", color=discord.Color.blue())
        embed.add_field(name="A Records", value="\n".join(a_records[2]), inline=False)
        
        await interaction.response.send_message(embed=embed)
    except socket.gaierror:
        await interaction.response.send_message(f"Could not resolve {domain}", ephemeral=True)
    except Exception as e:
        await interaction.response.send_message(f"Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="headers", description="Fetches and shows HTTP headers")
async def headers(interaction: discord.Interaction, url: str):
    if not url.startswith("http"):
        url = "http://" + url
    try:
        async with aiohttp.ClientSession() as session:
            async with session.head(url) as resp:
                headers_text = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                if len(headers_text) > 1900:
                    headers_text = headers_text[:1900] + "..."
                await interaction.response.send_message(f"```http\n{headers_text}\n```")
    except Exception as e:
        await interaction.response.send_message(f"Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="jwt_peek", description="Decodes a JWT payload (no verification)")
async def jwt_peek(interaction: discord.Interaction, token: str):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            await interaction.response.send_message("Invalid JWT format.", ephemeral=True)
            return
        
        payload = parts[1]
        # Fix padding
        payload += '=' * (-len(payload) % 4)
        decoded = base64.b64decode(payload).decode()
        parsed = json.loads(decoded)
        formatted = json.dumps(parsed, indent=2)
        
        await interaction.response.send_message(f"```json\n{formatted}\n```", ephemeral=True)
    except Exception as e:
        await interaction.response.send_message(f"Error decoding JWT: {str(e)}", ephemeral=True)

@bot.tree.command(name="json_fmt", description="Validates and pretty-prints JSON")
async def json_fmt(interaction: discord.Interaction, data: str):
    try:
        parsed = json.loads(data)
        formatted = json.dumps(parsed, indent=2)
        if len(formatted) > 1900:
            # Send as file if too long
            with open("formatted.json", "w") as f:
                f.write(formatted)
            await interaction.response.send_message("JSON is valid. Result too long, sending file.", file=discord.File("formatted.json"))
            os.remove("formatted.json")
        else:
            await interaction.response.send_message(f"```json\n{formatted}\n```")
    except json.JSONDecodeError:
        await interaction.response.send_message("Invalid JSON.", ephemeral=True)

@bot.tree.command(name="md5", description="Generates MD5 hash")
async def md5(interaction: discord.Interaction, text: str):
    h = hashlib.md5(text.encode()).hexdigest()
    await interaction.response.send_message(f"`{h}`")

@bot.tree.command(name="sha1", description="Generates SHA1 hash")
async def sha1(interaction: discord.Interaction, text: str):
    h = hashlib.sha1(text.encode()).hexdigest()
    await interaction.response.send_message(f"`{h}`")

@bot.tree.command(name="sha512", description="Generates SHA512 hash")
async def sha512(interaction: discord.Interaction, text: str):
    h = hashlib.sha512(text.encode()).hexdigest()
    await interaction.response.send_message(f"`{h}`")

@bot.tree.command(name="url_enc", description="URL encodes text")
async def url_enc(interaction: discord.Interaction, text: str):
    await interaction.response.send_message(f"`{urllib.parse.quote(text)}`")

@bot.tree.command(name="url_dec", description="URL decodes text")
async def url_dec(interaction: discord.Interaction, text: str):
    await interaction.response.send_message(f"`{urllib.parse.unquote(text)}`")

@bot.tree.command(name="rot13", description="Applies ROT13 cipher")
async def rot13(interaction: discord.Interaction, text: str):
    # Simple rot13 implementation
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    trans = chars[13:] + chars[:13] + chars[39:] + chars[26:39]
    table = str.maketrans(chars, trans)
    await interaction.response.send_message(f"`{text.translate(table)}`")

@bot.tree.command(name="caesar", description="Applies Caesar cipher")
async def caesar(interaction: discord.Interaction, text: str, shift: int):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            result += char
    await interaction.response.send_message(f"`{result}`")

@bot.tree.command(name="hex_enc", description="Converts text to hex")
async def hex_enc(interaction: discord.Interaction, text: str):
    await interaction.response.send_message(f"`{text.encode().hex()}`")

@bot.tree.command(name="hex_dec", description="Converts hex to text")
async def hex_dec(interaction: discord.Interaction, hex_str: str):
    try:
        text = bytes.fromhex(hex_str).decode()
        await interaction.response.send_message(f"`{text}`")
    except Exception:
        await interaction.response.send_message("Invalid hex string.", ephemeral=True)

@bot.tree.command(name="epoch", description="Converts Unix timestamp or shows current")
async def epoch(interaction: discord.Interaction, timestamp: Optional[int] = None):
    if timestamp is None:
        ts = int(time.time())
        await interaction.response.send_message(f"Current Epoch: `{ts}`")
    else:
        try:
            dt = datetime.datetime.fromtimestamp(timestamp)
            await interaction.response.send_message(f"Date: `{dt}`")
        except Exception:
            await interaction.response.send_message("Invalid timestamp.", ephemeral=True)

@bot.tree.command(name="curl", description="Fetches raw text content of a URL")
async def curl(interaction: discord.Interaction, url: str):
    if not url.startswith("http"):
        url = "http://" + url
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                text = await resp.text()
                if len(text) > 1900:
                    text = text[:1900] + "... (truncated)"
                await interaction.response.send_message(f"```\n{text}\n```")
    except Exception as e:
        await interaction.response.send_message(f"Error: {str(e)}", ephemeral=True)

# --- Basic Commands ---

@bot.tree.command(name="ping", description="Checks the bot's latency")
async def ping(interaction: discord.Interaction):
    latency = round(bot.latency * 1000)
    await interaction.response.send_message(f'Pong! {latency}ms')

@bot.tree.command(name="8ball", description="Ask the magic 8-ball a question")
async def eightball(interaction: discord.Interaction, question: str):
    responses = [
        "It is certain.", "It is decidedly so.", "Without a doubt.", "Yes - definitely.",
        "You may rely on it.", "As I see it, yes.", "Most likely.", "Outlook good.",
        "Yes.", "Signs point to yes.", "Reply hazy, try again.", "Ask again later.",
        "Better not tell you now.", "Cannot predict now.", "Concentrate and ask again.",
        "Don't count on it.", "My reply is no.", "My sources say no.",
        "Outlook not so good.", "Very doubtful."
    ]
    await interaction.response.send_message(f'🎱 **Question:** {question}\n**Answer:** {random.choice(responses)}')

# --- Fun Commands ---

@bot.tree.command(name="coinflip", description="Flips a coin")
async def coinflip(interaction: discord.Interaction):
    await interaction.response.send_message(f'🪙 {random.choice(["Heads", "Tails"])}')

@bot.tree.command(name="roll", description="Rolls a dice")
async def roll(interaction: discord.Interaction, sides: int = 6):
    await interaction.response.send_message(f'🎲 You rolled a {random.randint(1, sides)}')

@bot.tree.command(name="joke", description="Tells a random programming joke")
async def joke(interaction: discord.Interaction):
    jokes = [
        "Why do programmers prefer dark mode? Because light attracts bugs.",
        "How many programmers does it take to change a light bulb? None, that's a hardware problem.",
        "I would tell you a UDP joke, but you might not get it.",
        "There are 10 types of people in the world: those who understand binary, and those who don't.",
        "Why was the JavaScript developer sad? Because he didn't know how to 'null' his feelings."
    ]
    await interaction.response.send_message(random.choice(jokes))

@bot.tree.command(name="rps", description="Play Rock Paper Scissors")
async def rps(interaction: discord.Interaction, choice: Literal['rock', 'paper', 'scissors']):
    choices = ['rock', 'paper', 'scissors']
    bot_choice = random.choice(choices)
    
    result = "It's a tie!"
    if (choice == 'rock' and bot_choice == 'scissors') or \
       (choice == 'paper' and bot_choice == 'rock') or \
       (choice == 'scissors' and bot_choice == 'paper'):
        result = "You win!"
    elif choice != bot_choice:
        result = "I win!"
        
    await interaction.response.send_message(f"I chose {bot_choice}. {result}")

@bot.tree.command(name="choose", description="Randomly picks one option (separate with commas)")
async def choose(interaction: discord.Interaction, options: str):
    option_list = [opt.strip() for opt in options.split(',')]
    if len(option_list) < 2:
        await interaction.response.send_message("Please provide at least two options separated by commas.")
        return
    await interaction.response.send_message(f"I choose: {random.choice(option_list)}")

@bot.tree.command(name="reverse", description="Reverses the input text")
async def reverse(interaction: discord.Interaction, text: str):
    await interaction.response.send_message(text[::-1])

@bot.tree.command(name="mock", description="cOnVeRtS tExT tO mOcKiNg cAsE")
async def mock(interaction: discord.Interaction, text: str):
    mocked_text = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(text))
    await interaction.response.send_message(mocked_text)

@bot.tree.command(name="rate", description="Rates something 0-10")
async def rate(interaction: discord.Interaction, thing: str):
    rating = random.randint(0, 10)
    await interaction.response.send_message(f"I rate {thing} a {rating}/10")

@bot.tree.command(name="echo", description="Makes the bot repeat text")
async def echo(interaction: discord.Interaction, text: str):
    await interaction.response.send_message(text)

@bot.tree.command(name="lorem", description="Generates Lorem Ipsum text")
async def lorem(interaction: discord.Interaction):
    lorem_text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
    await interaction.response.send_message(lorem_text)

@bot.tree.command(name="ascii", description="Converts text to simple ASCII art")
async def ascii_art(interaction: discord.Interaction, text: str):
    art = ""
    for char in text:
        art += f"{char} "
    await interaction.response.send_message(f"```\n{art}\n```")

# --- Utility Commands ---

@bot.tree.command(name="avatar", description="Shows a user's avatar")
async def avatar(interaction: discord.Interaction, member: Optional[discord.Member] = None):
    member = member or interaction.user
    await interaction.response.send_message(member.avatar.url)

@bot.tree.command(name="userinfo", description="Shows info about a user")
async def userinfo(interaction: discord.Interaction, member: Optional[discord.Member] = None):
    member = member or interaction.user
    embed = discord.Embed(title="User Info", color=member.color)
    embed.set_thumbnail(url=member.avatar.url)
    embed.add_field(name="Name", value=member.name, inline=True)
    embed.add_field(name="ID", value=member.id, inline=True)
    embed.add_field(name="Joined", value=member.joined_at.strftime("%Y-%m-%d"), inline=True)
    embed.add_field(name="Created", value=member.created_at.strftime("%Y-%m-%d"), inline=True)
    embed.add_field(name="Roles", value=", ".join([role.name for role in member.roles if role.name != "@everyone"]), inline=False)
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="serverinfo", description="Shows info about the server")
async def serverinfo(interaction: discord.Interaction):
    guild = interaction.guild
    embed = discord.Embed(title="Server Info", color=discord.Color.blue())
    embed.add_field(name="Name", value=guild.name, inline=True)
    embed.add_field(name="Members", value=guild.member_count, inline=True)
    embed.add_field(name="Owner", value=str(guild.owner), inline=True)
    embed.add_field(name="Created", value=guild.created_at.strftime("%Y-%m-%d"), inline=True)
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="poll", description="Creates a reaction poll")
async def poll(interaction: discord.Interaction, question: str, option1: str, option2: str, option3: Optional[str] = None, option4: Optional[str] = None):
    options = [opt for opt in [option1, option2, option3, option4] if opt]
    
    reactions = ['1️⃣', '2️⃣', '3️⃣', '4️⃣']
    
    description = []
    for i, option in enumerate(options):
        description.append(f"{reactions[i]} {option}")
        
    embed = discord.Embed(title=question, description="\n".join(description), color=discord.Color.gold())
    await interaction.response.send_message(embed=embed)
    msg = await interaction.original_response()
    
    for i in range(len(options)):
        await msg.add_reaction(reactions[i])

@bot.tree.command(name="password", description="Generates a secure password")
async def password(interaction: discord.Interaction, length: int = 12):
    if length > 100:
        await interaction.response.send_message("Password too long!", ephemeral=True)
        return
    chars = string.ascii_letters + string.digits + string.punctuation
    pwd = ''.join(random.choice(chars) for _ in range(length))
    try:
        await interaction.user.send(f"Your generated password: ||{pwd}||")
        await interaction.response.send_message("Sent you a DM with the password.", ephemeral=True)
    except discord.Forbidden:
        await interaction.response.send_message("I couldn't DM you. Please check your privacy settings.", ephemeral=True)

@bot.tree.command(name="base64", description="Encodes or decodes Base64")
async def base64_cmd(interaction: discord.Interaction, mode: Literal['encode', 'decode'], text: str):
    try:
        if mode == 'encode':
            encoded = base64.b64encode(text.encode()).decode()
            await interaction.response.send_message(f"Encoded: `{encoded}`")
        else:
            decoded = base64.b64decode(text).decode()
            await interaction.response.send_message(f"Decoded: `{decoded}`")
    except Exception as e:
        await interaction.response.send_message(f"Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="hash", description="Generates SHA-256 hash")
async def hash_cmd(interaction: discord.Interaction, text: str):
    hashed = hashlib.sha256(text.encode()).hexdigest()
    await interaction.response.send_message(f"SHA-256: `{hashed}`")

@bot.tree.command(name="length", description="Counts characters in text")
async def length(interaction: discord.Interaction, text: str):
    await interaction.response.send_message(f"Length: {len(text)} characters")

@bot.tree.command(name="binary", description="Converts text to binary")
async def binary(interaction: discord.Interaction, text: str):
    binary_str = ' '.join(format(ord(c), '08b') for c in text)
    await interaction.response.send_message(f"Binary: `{binary_str}`")

@bot.tree.command(name="hex", description="Previews a hex color")
async def hex_cmd(interaction: discord.Interaction, color_code: str):
    if color_code.startswith('#'):
        color_code = color_code[1:]
    
    try:
        color_int = int(color_code, 16)
        embed = discord.Embed(title=f"Hex: #{color_code}", color=color_int)
        await interaction.response.send_message(embed=embed)
    except ValueError:
        await interaction.response.send_message("Invalid hex code.", ephemeral=True)

@bot.tree.command(name="uptime", description="Shows bot uptime")
async def uptime(interaction: discord.Interaction):
    current_time = time.time()
    uptime_seconds = int(current_time - start_time)
    uptime_string = str(datetime.timedelta(seconds=uptime_seconds))
    await interaction.response.send_message(f"Uptime: {uptime_string}")

@bot.tree.command(name="uuid", description="Generates a random UUID")
async def uuid_cmd(interaction: discord.Interaction):
    await interaction.response.send_message(f"UUID: `{uuid.uuid4()}`")

@bot.tree.command(name="math", description="Evaluates a math expression")
async def math_cmd(interaction: discord.Interaction, expression: str):
    allowed_chars = set("0123456789+-*/(). ")
    if not set(expression).issubset(allowed_chars):
        await interaction.response.send_message("Invalid characters in expression.", ephemeral=True)
        return
    try:
        result = eval(expression, {"__builtins__": None}, {})
        await interaction.response.send_message(f"Result: {result}")
    except Exception:
        await interaction.response.send_message("Error evaluating expression.", ephemeral=True)

@bot.tree.command(name="purge", description="Deletes messages (Admin only)")
@app_commands.checks.has_permissions(manage_messages=True)
async def purge(interaction: discord.Interaction, amount: int):
    await interaction.response.defer(ephemeral=True)
    await interaction.channel.purge(limit=amount)
    await interaction.followup.send(f"Purged {amount} messages.", ephemeral=True)

# --- VirusTotal ---

@bot.tree.command(name="scan", description="Scan a file with VirusTotal")
async def scan(interaction: discord.Interaction, attachment: discord.Attachment):
    if not VIRUSTOTAL_API_KEY:
        await interaction.response.send_message("VirusTotal API key not configured.", ephemeral=True)
        return

    await interaction.response.send_message(f"Scanning {attachment.filename}...", ephemeral=True)

    # Download file
    async with aiohttp.ClientSession() as session:
        async with session.get(attachment.url) as resp:
            if resp.status != 200:
                await interaction.followup.send("Failed to download file.", ephemeral=True)
                return
            data = await resp.read()

    # Upload to VirusTotal
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    form_data = aiohttp.FormData()
    form_data.add_field('file', data, filename=attachment.filename)

    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, data=form_data) as resp:
            if resp.status != 200:
                error_text = await resp.text()
                await interaction.followup.send(f"VirusTotal upload failed: {resp.status} - {error_text}", ephemeral=True)
                return
            json_resp = await resp.json()
            analysis_id = json_resp['data']['id']

    await interaction.followup.send("File uploaded. Waiting for results...", ephemeral=True)

    # Poll for results
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    for _ in range(10): # Try 10 times
        await asyncio.sleep(5)
        async with aiohttp.ClientSession() as session:
            async with session.get(analysis_url, headers=headers) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    status = result['data']['attributes']['status']
                    if status == 'completed':
                        stats = result['data']['attributes']['stats']
                        malicious = stats['malicious']
                        harmless = stats['harmless']
                        
                        color = discord.Color.green() if malicious == 0 else discord.Color.red()
                        embed = discord.Embed(title="Scan Results", color=color)
                        embed.add_field(name="File", value=attachment.filename)
                        embed.add_field(name="Malicious", value=malicious)
                        embed.add_field(name="Harmless", value=harmless)
                        embed.set_footer(text="Powered by VirusTotal")
                        
                        await interaction.followup.send(embed=embed)
                        return
    
    await interaction.followup.send("Scan timed out or is still processing. Check back later.", ephemeral=True)

if __name__ == '__main__':
    if TOKEN:
        bot.run(TOKEN)
    else:
        print("Please set DISCORD_TOKEN in .env")
