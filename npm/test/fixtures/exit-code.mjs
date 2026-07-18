const code = Number.parseInt(process.argv[2] ?? "1", 10);
process.exit(Number.isInteger(code) ? code : 1);
