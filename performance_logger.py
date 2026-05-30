import psutil
import csv
import os
import time

process = psutil.Process(os.getpid())

with open("performance_log.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["time", "cpu_percent", "memory_mb"])

    t = 0
    while True:
        cpu = process.cpu_percent(interval=1)
        mem = process.memory_info().rss / (1024 * 1024)

        writer.writerow([t, cpu, mem])
        f.flush()

        print(f"CPU: {cpu}% | RAM: {mem:.2f} MB")

        t += 1
