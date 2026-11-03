.PHONY: build up down restart logs shell smoke

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

restart:
	docker compose restart

logs:
	docker compose logs -f --tail=200

shell:
	docker compose exec admin bash

smoke:
	bash scripts/smoke.sh
