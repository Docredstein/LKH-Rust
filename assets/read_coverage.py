import json

with open("./coverage.json", "r") as file:
    report = json.load(file)

result = report["data"][0]["totals"]["lines"]["percent"]
print(f"{result:.2f}")
