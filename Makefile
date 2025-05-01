# lint: 
# 	docker run --rm -t -v `pwd`/integration/:/data/integration/ auth0/marketplace-integration-tools npm run integration:lint

lint1: 
	docker run --rm -t -v `pwd`/integration-1/:/data/integration/ auth0/marketplace-integration-tools npm run integration:lint

lint2: 
	docker run --rm -t -v `pwd`/integration-2/:/data/integration/ auth0/marketplace-integration-tools npm run integration:lint

# test: 
# 	docker run --rm -t -v `pwd`/integration/:/data/integration/ auth0/marketplace-integration-tools npm run test:action

test1: 
	docker run --rm -t -v `pwd`/integration-1/:/data/integration/ auth0/marketplace-integration-tools npm run test:action

test2: 
	docker run --rm -t -v `pwd`/integration-2/:/data/integration/ auth0/marketplace-integration-tools npm run test:action

# zip: 
# 	zip -r integration-action.zip integration media

zip1: 
	zip -r integration-action1.zip integration-1 media

zip2: 
	zip -r integration-action2.zip integration-2 media

deploy_init:
	docker run --rm -it -v `pwd`/integration/:/data/integration/ -v `pwd`/deploy:/data/deploy auth0/marketplace-integration-tools bash deploy-scripts/init.sh

deploy_get_token:
	docker run --rm -t -v `pwd`/integration/:/data/integration/ -v `pwd`/deploy:/data/deploy auth0/marketplace-integration-tools bash deploy-scripts/get-token.sh

deploy_create:
	docker run --rm -t -v `pwd`/integration/:/data/integration/ -v `pwd`/deploy:/data/deploy auth0/marketplace-integration-tools bash deploy-scripts/action-create.sh

deploy_get:
	docker run --rm -t -v `pwd`/integration/:/data/integration/ -v `pwd`/deploy:/data/deploy auth0/marketplace-integration-tools bash deploy-scripts/action-get.sh

deploy_get_all:
	docker run --rm -t -v `pwd`/integration/:/data/integration/ -v `pwd`/deploy:/data/deploy auth0/marketplace-integration-tools bash deploy-scripts/action-get-all.sh

deploy_update:
	docker run --rm -t -v `pwd`/integration/:/data/integration/ -v `pwd`/deploy:/data/deploy auth0/marketplace-integration-tools bash deploy-scripts/action-update.sh

deploy_delete:
	docker run --rm -t -v `pwd`/integration/:/data/integration/ -v `pwd`/deploy:/data/deploy auth0/marketplace-integration-tools bash deploy-scripts/action-delete.sh