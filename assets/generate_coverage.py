import os
import json

os.system("cargo llvm-cov nextest --json --output-path ./target/coverage.json")

with open("./target/coverage.json", "r") as file:
    report = json.load(file)

result = report["data"][0]["totals"]["lines"]["percent"]
print(f"Code coverage : {result}")
os.system(f"coverage-badge -c {float(result):.2f} -o assets/coverage.svg")
