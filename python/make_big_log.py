# make_big_log.py: generate a test log with one clear outlier
lines = []


def add(ip, n):
    for i in range(n):
        lines.append(
            f"Jan 15 03:{i % 60:02d}:00 server01 sshd[2000]: "
            f"Failed password for root from {ip} port {40000 + i} ssh2"
        )


add("203.0.113.7", 50)
for i, n in enumerate([2, 1, 1, 2, 1, 1, 2], start=10):
    add(f"198.51.100.{i}", n)

with open("big_auth.log", "w") as f:
    f.write("\n".join(lines) + "\n")
print(f"Wrote {len(lines)} lines to big_auth.log")
