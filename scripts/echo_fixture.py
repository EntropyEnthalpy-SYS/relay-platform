#!/usr/bin/env python3
"""Local TCP/UDP echo target for manual acceptance. No filesystem is served."""
import argparse
import asyncio


async def echo(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        writer.close()


class DatagramEcho(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, peer):
        self.transport.sendto(data, peer)


async def main(port):
    server = await asyncio.start_server(echo, '127.0.0.1', port)
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        DatagramEcho, local_addr=('127.0.0.1', port))
    print(f'TCP/UDP echo: 127.0.0.1:{port}', flush=True)
    try:
        async with server:
            await server.serve_forever()
    finally:
        transport.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=19000)
    args = parser.parse_args()
    try:
        asyncio.run(main(args.port))
    except KeyboardInterrupt:
        pass
