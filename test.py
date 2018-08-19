import asyncio
import aiopg


async def async_main():
    dsn = "dbname=test user=postgres password=proxy_mysecret host=127.0.0.1 port=7777"

    pool = await aiopg.create_pool(dsn)
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT 1")
            ret = []
            async for row in cur:
                ret.append(row)
            assert ret == [(1,)]


def main():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(async_main())
    loop.run_forever()


if __name__ == "__main__":
    main()
