.PHONY: run_app
run_app: migrate_db
	. ./config.sh && cd backend && docker-compose up

.PHONY: test_app
test_app: migrate_db
	. ./config.sh && cd backend && docker-compose run web bash -c 'PYTHONPATH=. DATABASE_URL="sqlite:///:memory:" REDIS_URL="redis://cache" pytest -vv'

# rebuild the app container (this usually is only necessary if dependencies change, because docker-compose.yml defines a volume that uses ./backend as /app/backend directly, so changes in that folder are reflected inside the container instantly)
.PHONY: build_app
build_app: migrate_db
	. ./config.sh && cd backend && docker-compose build

.PHONY: migrate_db
migrate_db:
	. ./config.sh && cd backend && docker-compose run web bash -c 'FLASK_APP=models.py flask db upgrade'

.PHONY: create_migration_db
create_migration_db:
	. ./config.sh && cd backend && docker-compose run web bash -c 'read -p "Migration description: " MESSAGE && FLASK_APP=models.py flask db migrate -m "$$MESSAGE"'

.PHONY: nuke_db
nuke_db:
	. ./config.sh && cd backend && docker-compose run web bash -c 'PYTHONPATH=. python3 -c "from models import db; db.reflect(); db.drop_all()"'
	. ./config.sh && cd backend && docker-compose run web bash -c 'PYTHONPATH=. python3 -c "import caching; caching.clear_all()"'

.PHONY: create_test_user
create_test_user: migrate_db
	. ./config.sh && cd backend && docker-compose run web bash -c 'PYTHONPATH=. python3 create_test_user.py'

.PHONY: create_test_promo
create_test_promo: migrate_db
	. ./config.sh && cd backend && docker-compose run web bash -c 'PYTHONPATH=. python3 create_test_promo.py'

.PHONY: enter_web
enter_web:
	. ./config.sh && cd backend && docker-compose run web bash

.PHONY: enter_db
enter_db:
	cd backend && docker-compose run db bash -c 'PGPASSWORD=$$POSTGRES_PASSWORD psql -h db -U forecast'

.PHONY: provision
provision:
	cd provision && terraform init && terraform apply -var-file="prod.tfvars"
