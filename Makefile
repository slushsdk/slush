build:
	protostar build --disable-hint-validation
test:
	protostar test ./tests
vim:
	vim src/main.cairo
vimt:
	vim tests/test_main.cairo
push:
	git push -u origin main
rebase:
	git pull --rebase
