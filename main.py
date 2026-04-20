"""
Local fallback scheduler — only needed if you are NOT using the Claude Code
remote schedule (which is the recommended approach).

The Claude Code daily schedule (xsiam-threat-intel-daily) runs pipeline.py
automatically every day at 6 AM UTC from Anthropic's cloud.
Manage it at: https://claude.ai/code/scheduled

To run locally instead (keep this terminal open):
    python main.py
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
    trigger = CronTrigger(hour=settings.schedule_hour, minute=settings.schedule_minute, timezone="UTC")
    scheduler.add_job(scheduled_run, trigger, id="threat_intel_pipeline", replace_existing=True)
    scheduler.start()

    logger.info(
        f"Local scheduler started — pipeline fires daily at "
        f"{settings.schedule_hour:02d}:{settings.schedule_minute:02d} UTC. "
        f"Close terminal to stop."
    )

    try:
        while True:
            await asyncio.sleep(3600)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
        logger.info("Scheduler stopped.")


if __name__ == "__main__":
    asyncio.run(main())
