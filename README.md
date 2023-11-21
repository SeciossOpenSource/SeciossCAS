# SeciossCAS

## 概要
クラウドサービスのセキュリティ対策に必要な情報を取得できるPythonモジュールです。
Secioss CAS(Cloud App Security)は、以下の機能を提供するオープンソースのモジュールが含まれています。

### seciossauditlog
クラウドサービスのログの収集

### seciosssecuritycheck
IaaSクラウドサービスの設定情報収集と比較

## 動作環境
* OS：Rockey Linux8、Redhat Enterprise Linux 8

## インストール
### 事前準備
`# dnf install python39 python3-boto3 python3-jwt`

### パッケージインストール
`# dnf install packages/seciossaudit-0.2.0-8202.el8.noarch.rpm`

`# dnf install packages/seciosssecuritycheck-0.2.0-8202.el8.noarch.rpm`

## 動作確認準備
### seciossauditlog
作業ディレクトリにsample.pyを移動します。
`# cp scripts/sample.py work`

同じディレクトリに設定ファイルsample.iniを作成します。
内容は以下のようにサービスをセクションにして各パラメータを記載してください。

```
[AWS]
region = ap-northeast-1
access_key = xxxxxxxxxxxxx
secret_key = xxxxxxxxxxxxx
```

サービス毎のサービスIDと必要なパラメータは以下の通りです。
#### Amazon Web Service
サービスID：AWS
必要なパラメータ
region：リージョン
access_key: CloudTrailが閲覧可能なユーザーのアクセスキー
secret_key: CloudTrailが閲覧可能なユーザーのシークレットキー

#### Box
サービスID：Box
必要なパラメータ
client_id: APIにアクセスするカスタムアプリのクライアントID
client_secret: APIにアクセスするカスタムアプリのクライアントシークレット
refresh_token: 上記クライアントIDで取得したリフレッシュトークン
token_url： https://app.box.com/api/oauth2/token

#### Dropbox
サービスID：Dropbox
必要なパラメータ
client_id: APIにアクセスするDropboxのアプリで設定したクライアントID
client_secret: APIにアクセスするDropboxのアプリで設定したクライアントシークレット
refresh_token: 上記クライアントIDで取得したリフレッシュトークン
token_url：https://api.dropbox.com/oauth2/token

#### GoogleWorkSpace
サービスID：Googleapps
必要なパラメータ
client_id: APIにアクセスするプロジェクトのサービスアカウントのクライアントID
prn: APIにアクセスするプロジェクトのサービスアカウントのメールアドレス
certificate: APIにアクセスするプロジェクトのサービスアカウントの秘密鍵

#### LINEWORKS
サービスID：Lineworks
必要なパラメータ
client_id: APIにアクセスするアプリのクライアントID
client_secret: APIにアクセスするアプリのクライアントシークレット
domain_id: Domain ID
service_account: APIにアクセスするアプリのサービスアカウント
certificate：

#### Microsoft 365
サービスID：Office365
必要なパラメータ
client_id: APIにアクセスするAzureアプリのアプリケーションID
client_secret: APIにアクセスするアプリのクライアントシークレット
directory_id: APIにアクセスするAzureアプリのディレクトリID

#### Salesforce
サービスID：Salesforce
必要なパラメータ
client_id: APIのクライアントID
client_secret: APIのクライアントシークレット
admin: 管理者ID
admin_password: 管理者IDのパスワード
token：管理者のセキュリティトークン

#### Zendesk
サービスID：Zendesk
必要なパラメータ
admin: 管理者ユーザー
token: APIにアクセスするためのトークン
subdomain: サブドメイン
service_account: APIにアクセスするアプリのサービスアカウント
certificate：

### seciosssecuritycheck
作業ディレクトリにsample.pyを移動します。
`# cp scripts/sample.py work`

同じディレクトリに設定ファイルsample.iniを作成します。
内容は以下のようにサービスをセクションにして各パラメータを記載してください。

```
[AWS]
access_key = xxxxxxxxxxxxx
secret_key = xxxxxxxxxxxxx
```

サービス毎のサービスIDと必要なパラメータは以下の通りです。
#### Amazon Web Service
サービスID：AWS
必要なパラメータ
access_key: 各サービスの設定が閲覧可能なユーザーのアクセスキー
secret_key: 各サービスの設定が閲覧可能なユーザーのシークレットキー

#### Azure
サービスID：Azure
必要なパラメータ
client_id: APIにアクセスするAzureアプリのアプリケーションID
client_secret: APIにアクセスするアプリのクライアントシークレット
directory_id: APIにアクセスするAzureアプリのディレクトリID

#### Google Cloud Platform
サービスID：Gcp
必要なパラメータ
iss: APIにアクセスするプロジェクトのサービスアカウントのクライアントID
prn: APIにアクセスするプロジェクトのサービスアカウントのメールアドレス
certificate: APIにアクセスするプロジェクトのサービスアカウントの秘密鍵


## 動作確認
以下のように実行すると標準出力に結果が表示されます。
### seciossauditlog
`# python3 sample.py`

### seciosssecuritycheck
/opt/secioss/etc/securitycheck配下に置かれている設定に基づいて判定します。
`# python3 sample.py`

