import matplotlib.pyplot as plt
import csv

time_vals = []
cpu = []

with open("performance_log.csv") as f:
    reader = csv.DictReader(f)

    for row in reader:
        time_vals.append(int(row["time_seconds"]))
        cpu.append(float(row["cpu_percent"]))

plt.plot(time_vals, cpu, label="CPU Usage (%)")

plt.xlabel("Time (seconds)")
plt.ylabel("Usage (%)")
plt.title("PyScan Performance Monitoring")
plt.legend()

plt.show()
