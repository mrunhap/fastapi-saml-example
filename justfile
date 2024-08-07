default:
    just --list

run:
    @source .venv/bin/activate && uvicorn main:app --reload --port 8080
