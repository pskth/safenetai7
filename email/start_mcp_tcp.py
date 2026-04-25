import asyncio
import os
import sys

# Windows requires this for ProactorEventLoop when spawning subprocesses
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

async def handle_client(reader, writer):
    print(f"\n[+] Client connected from {writer.get_extra_info('peername')}")
    print("[*] Spawning VT MCP subprocess...")
    
    env = os.environ.copy()
    command_line = "npx.cmd -y @burtthecoder/mcp-virustotal"
    
    process = await asyncio.create_subprocess_shell(
        command_line,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )

    async def forward(src, dst, direction):
        try:
            while True:
                data = await src.read(4096)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        except Exception as e:
            pass

    # Forward TCP -> Process STDIN and Process STDOUT -> TCP
    await asyncio.gather(
        forward(reader, process.stdin, "TCP -> STDIN"),
        forward(process.stdout, writer, "STDOUT -> TCP")
    )
    
    try:
        process.terminate()
    except Exception:
        pass
    print("[-] Client disconnected.")

async def main():
    host = '127.0.0.1'
    port = 8081
    server = await asyncio.start_server(handle_client, host, port)
    
    print("=" * 50)
    print(f" MCP Server TCP Bridge Running on {host}:{port}")
    print(" Run this script in a separate terminal!")
    print("=" * 50)
    
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
