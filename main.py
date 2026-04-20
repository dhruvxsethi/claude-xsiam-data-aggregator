"""
Entry point: starts the APScheduler and runs the pipeline on schedule.
Run with: python main.py
"""

import asyncio
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from loguru import logger

from config import settings
from pipeline import run_pipeline


async def scheduled_run():
    logger.info("=== Scheduled pipeline run starting ===")
    try:
        summary = await run_pipeline()
        logger.info(f"=== Run complete: {summary} ===")
    except Exception as e:
        logger.error(f"=== Pipeline run failed: {e} ===")


async def main():
    scheduler = AsyncIOScheduler()

    trigger = CronTrigger(
        hour=settings.schedule_hour,
        minute=settings.schedule_minute,
        timezone="UTC",
    )

    scheduler.add_job(scheduled_run, trigger, id="threat_intel_pipeline", replace_existing=True)
    scheduler.start()

    logger.info(
        f"Scheduler started — pipeline will run daily at "
        f"{settings.schedule_hour:02d}:{settings.schedule_minute:02d} UTC"
    )
    logger.info("Run 'python pipeline.py' to trigger immediately without waiting for the schedule.")

    # Keep the event loop alive
    try:
        while True:
            await asyncio.sleep(3600)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
        logger.info("Scheduler stopped.")


if __name__ == "__main__":
    asyncio.run(main())
