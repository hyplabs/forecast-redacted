Forecast
==========

Forecast is a fully featured prediction market where users can bet on the prices of different cryptocurrencies. The platform is secure and fully auditable. This is a redacted version approved for distribution by Hypotenuse. 

API
------

#### Health check
##### GET /api/healthcheck

Request
```
```

Response
```
{
  status: 'success'
}
```

#### Register
##### POST /api/register

Request
```
{
  email: string,
  username: string,
  phone: string,
  password: string,
  bank_name: string,
  bank_account_number: string,
  referral_code: string,
}
```
*Note: phone must be in [E.164 format](https://www.twilio.com/docs/glossary/what-e164)*

Response
```
{
  status: 'success' | 'failure',
  user: { ... } | undefined
}
```

#### Check username available
##### POST /api/register/check

Request
```
{
  username: string
}
```

Response
```
{
  status: 'success' | 'failure',
  error: undefined | 'User with provided username already exists'
}
```

#### Send OTP to phone number for verification
##### POST /api/send_sms_verification

Request
```
{
  phone: string
}
```

Response
```
{
  status: 'success' | 'failure',
}
```

#### Verify phone number using OTP
##### POST /api/verify_phone

Request
```
{
  phone: string,
  otp: string,
}
```

Response
```
{
  status: 'success' | 'failure',
  error: undefined | 'No active verification code' | 'Incorrect verification code'
}
```

#### Verify email using verification code
##### POST /api/verify_email

Request
```
{
  verification_code: string
}
```

Response
```
{
  status: 'success' | 'failure'
}
```

#### Login
##### POST /api/login

Request
```
{
  username: string,
  password: string
}
```

Response
```
{
  status: 'success',
  user: { ... } | undefined
}
```

#### Start forgot password flow
##### POST /api/login/forgot

Request
```
{
  email: string
}
```

Response
```
{
  status: 'success' | 'failure',
}
```

#### Reset password
##### POST /api/login/forgot

Request
```
{
  email: string,
  otp: string,
  new_password: string,
  new_password_confirmation: string
}
```

Response
```
{
  status: 'success' | 'failure',
  error: undefined | 'No active password reset' | 'Incorrect verification code' | 'New password does not equal new password confirmation'
}
```

#### Logout
##### POST /api/logout
*Login Required*

Request
```
```

Response
```
{
  status: 'success'
}
```

#### Get user profile
##### GET /api/me

Request
```
```

Response
```
{
  status: 'success',
  user: undefined | {
    id: int,
    email: string,
    email_confirmed: bool,
    username: string,
    phone: string,
    bank_name: string,
    bank_account_number: string,
    balance: int
  }
}
```

#### Edit user profile
##### PATCH /api/me
*Login Required*

Request
```
{
  email: string,
  password: string,
  new_password: string,
  new_password_confirmation: string,
}
```

Response
```
{
  status: 'success' | 'failure',
  error: undefined | 'Incorrect password entered' | 'New password does not equal new password confirmation',
  user: undefined | { ... }
}
```
*Note: If new_password is empty, password won't be changed. If email is the same, email won't be changed.*

#### Get user transactions
##### GET /api/me/transactions
*Login Required*

Request
```
```

Response
```
{
  status: 'success',
  transactions: [
    {
      id: int,
      user_id: int,
      transaction_type: string,
      amount: int,
      status: string,
      notes: string,
      created_at: Date
    }
  ]
}
```

#### Create new deposit
##### POST /api/me/transactions/deposits
*Login Required*

Request
```
{
  amount: int
}
```

Response
```
{
  status: 'success',
  transaction: { ... }
}
```

#### Create new withdrawal
##### POST /api/me/transactions/withdrawals
*Login Required*

Request
```
{
  amount: int
}
```

Response
```
{
  status: 'success',
  transaction: { ... }
}
```

#### Create/update/delete current bet
##### POST /api/me/bet
*Login Required*

Request
```
{
  round_id: int,
  bet_type: string,
  amount: int
}
```

Response
```
{
  status: 'success' | 'failure',
  error: undefined | 'Bet type TYPE does not exist.' | 'Cannot bet less than minimum bet amount 10000.' | 'Cannot bet more money than is in user balance.' | 'Round 123 does not exist.' | 'Round 123 currently not in the betting period.',
  message: undefined | 'Bet 123 deleted.',
  bet: undefined | { ... }
}
```
*Note: To delete the current bet, pass in 0 as the bet amount.

#### Get user bet history
##### GET /api/bet
*Login Required*

Request
```
```

Response
```
{
  status: 'success',
  bets: [
    {
      id: int,
      user_id: int,
      round_id: int,
      bet_type: string,
      amount: int,
      created_at: Date,
      updated_at: Date,
    }
  ]
}
```

#### Get list of current rounds
##### GET /api/round
*Login Required*

Request
```
```

Response
```
{
  status: 'success',
  rounds: [
    {
      id: int,
      round_date: Date,
      round_number: int,
      start_time: Date,
      lock_in_bets_time: Date,
      end_time: Date,
      start_price: Float,
      end_price: Float,
      round_result: string,
      round_result_decided_time: Date,
      exchange_id: id,
      round_status: string,
      created_at: Date,
      updated_at: Date
    }
  ]
}
```

Development
-----------

First, get a copy of `config.sh` from HypLabs. This contains all of the secret values you will need for access to SendGrid, Twilio, and more.

You can now run the following commands for common development tasks:

* `make test_app` runs all tests, within a Docker container.
* `make run_app` starts the entire application via Docker Compose, including the backend, price updater, admin UI, Redis, and PostgreSQL. This is what you will usually use to run the app.
* `make build_app` rebuilds the Docker images for the application. This usually should only be necessary if you've changed the application dependencies (`backend/requirements.txt` or `backend/Dockerfile`) - the application code is directly mounted into the container, so code changes are visible within the container immediately.
* `make migrate_db` runs database migrations that haven't been applied yet, using Alembic inside a Docker container. Typically you would run this after new migrations have been written, and before running new code that depends on the migration being present.
* `make create_migration_db` creates a skeleton Python file for a migration using Alembic's migration autogeneration. The new migration file can be in `backend/migrations/versions`. You can fill out this skeleton to save time when writing migrations.
* `make nuke_db` destroys all tables in the PostgreSQL database. This should only be used for testing and developing migrations - otherwise, database changes should only be done using `make migrate_db` and migrations.
* `make create_test_user` creates some test users in the database. This is often useful for testing since the registration process is otherwise relatively long.
* `make enter_web` enters a bash shell inside the Docker image for the backend. This is useful for testing out commands in the exact same environment that the backend runs in, including the ability to run one-off Python snippets and access the database.
* `make enter_db` opens a `psql` shell inside the Docker image for the backend. In this shell, you can directly execute SQL statements against the database - very useful for testing and development.
* `make provision` runs Terraform to provision the production infrastructure. This requires additional credentials to work - see details below in the "Devops" section.

Devops
------

First, get a copy of `provisioning/prod.tfvars` and `provisioning/devhost-key.pem` from HypLabs. These contain all of the secret values you will need for access to production infrastructure, devhost, SendGrid, Twilio, and more.

Provisioning infrastructure:

```bash
make provision
```

Descriptions:

* `backend-repository-url`: AWS Elastic Container Registry repository URL that Forecast application Docker images can be pushed to.
* `database-url`: the URL of the PostgreSQL database, including login credentials.
* `devhost-login-command`: the command that you use to connect to the devhost machine - a plain Linux server within the private subnet that we use to run migrations, run one-off commands on prod, and so on.
* `redis-url`: the URL of the Redis cache.
* `vpc-id`: ID of the AWS VPC that everything runs inside.

Deploying a new version of the application:

```bash
export AWS_ACCESS_KEY_ID=TODO
export AWS_SECRET_ACCESS_KEY=TODO
export AWS_DEFAULT_REGION="us-east-2"
export AWS_ECR_URL="$(aws sts get-caller-identity --query Account --output text).dkr.ecr.$AWS_DEFAULT_REGION.amazonaws.com"
aws ecr get-login-password --region $AWS_DEFAULT_REGION | docker login --username AWS --password-stdin $AWS_ECR_URL
cd backend
docker build . -t $AWS_ECR_URL/backend-repository
docker push $AWS_ECR_URL/backend-repository
cd ..

# MANUAL STEP: run migrations using the devhost: SSH into the devhost, then `source forecast.devhost.sh; forecast-migrate`
# MANUAL STEP: if you've changed the way Redis caching works, you may want to clear the Redis cache: SSH into the devhost, then `source forecast.devhost.sh; forecast-shell`, then inside the shell, run `python -c 'import caching; print(caching.redis_client.flushall())'` (the Redis cache will be repopulated when the price updater starts)

# force ECS service to refresh the docker container
aws ecs update-service --cluster fargate-cluster --service backend-service --force-new-deployment | jq '.service.deployments'
aws ecs update-service --cluster fargate-cluster --service price-updater-service --force-new-deployment | jq '.service.deployments'
aws ecs update-service --cluster fargate-cluster --service admin-service --force-new-deployment | jq '.service.deployments'

# MANUAL STEP: push out new frontend to AWS Amplify with `git push aws master` where `aws` is a Git remote you can add with `git remote add https://CODECOMMIT_USERNAME:CODECOMMIT_PASSWORD@git-codecommit.us-east-2.amazonaws.com/v1/repos/forecast` (you can get `CODECOMMIT_USERNAME` and `CODECOMMIT_PASSWORD` from HypLabs)
```

Infra setup steps:

1. Register the domain `forecast.example.com` on AWS Route53.
2. Run Terraform: `make provision`.
3. Create a CodeCommit repository and push codebase there: https://us-east-2.console.aws.amazon.com/codesuite/codecommit/repositories/forecast/browse?region=us-east-2. This is because AWS Amplify doesn't work with GitHub unless it has access to your entire GitHub account, which is not acceptable.
4. Set up IAM user with CodeCommit access (the `AWSCodeCommitPowerUser` policy), then create CodeCommit Git credentials that can be used to push to the CodeCommit repository.
5. Set up CI with AWS Amplify, connected to the CodeCommit repository (build config is at `./amplify.yml`).
6. Set up AWS Amplify with the `forecast.example.com` domain with the root domain and `www` subdomain, and set up HTTPS.
7. Change the "Rewrites and redirects" rules in the AWS Amplify app:
    * Add support for SPAs, using slightly modified instructions from https://docs.aws.amazon.com/amplify/latest/userguide/redirects.html#redirects-for-single-page-web-apps-spa: `</^[^.]+$|\.(?!(css|gif|ico|jpg|js|png|txt|svg|woff|woff2|ttf|map|json|html)$)([^.]+$)/>` -> `/index.html` (200 Rewrite).
    * Redirect www to root: `https://www.forecast.example.com` -> `https://forecast.example.com` (301 Redirect).
8. Authenticate domain with Sendgrid Sender Authentication: https://app.sendgrid.com/settings/sender_auth
9. Set up `TXT` and `MX` records for GSuite to be able to send and receive mail from support@forecast.example.com - instructions available when you attempt to log into GSuite for support@forecast.example.com.
10. Running a copy of the codebase on the devhost:
    1. Get a copy of `config.devhost.sh` from HypLabs.
    2. Install Docker: `sudo yum install -y docker; sudo service docker start`
    3. Remove outdated AWS CLI: `sudo yum remove -y awscli`.
    4. Install AWS CLI v2 (Amazon Linux 2 includes only 1.16, which is too old): https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2-linux.html#cliv2-linux-install
    5. Run the following commands: `source forecast.devhost.sh; forecast-shell`. You are now in a shell inside an instance of the Forecast Docker container.
    6. Install psql and redis-cli on the devhost for debugging purposes.
11. Set up CI on the CodeCommit repository using AWS CodeBuild, with [Docker Layer Cache](https://docs.aws.amazon.com/codebuild/latest/userguide/build-caching.html#caching-local), and the `AmazonEC2ContainerRegistryFullAccess` policy attached to the generated IAM Service Role.
