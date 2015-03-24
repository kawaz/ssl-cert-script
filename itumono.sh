#!/bin/bash

##ユーティリティ関数定義
function echo_red()     { echo -e "\033[0;31m$@\033[0m"; }
function echo_green()   { echo -e "\033[0;32m$@\033[0m"; }
function echo_yellow()  { echo -e "\033[0;33m$@\033[0m"; }
function echo_blue()    { echo -e "\033[0;34m$@\033[0m"; }
function echo_magenta() { echo -e "\033[0;35m$@\033[0m"; }
function echo_cyan()    { echo -e "\033[0;36m$@\033[0m"; }
function echo_debug()   { echo "$@"; }
function echo_info()    { echo_green "$@"; }
function echo_warn()    { echo_magenta "$@"; }
function echo_error()   { echo_red "$@"; }

## カレントディレクトリ移動
cd "$(dirname "$0")" || exit 1

##configファイルチェック
if [[ ! -f config ]]; then
  echo_debug "make ./config"
  cp config.sample config
fi
if diff -bB config config.sample >/dev/null 2>&1; then
  echo_error "Please edit ./config."
  exit 1
fi

##パスフレーズ自動化用関数
function autopass() {
  if type expect >/dev/null 2>&1; then
    # expectが使えるならパスフレーズを自動入力する
    expect -c "
      spawn $*
      expect {
        \"Enter pass phrase for \" {
          send \"$PASSPHRASE\n\"
          exp_continue
        }
      }
    "
  else
    # expectが無いので普通に実行する
    echo_warn "パスフレーズが何度も聞かれるのが面倒なら yum install expect してから再実行してください"
    "$@"
  fi
}

##パスフレーズを保存
if [[ ! -f server.key.passphrase ]]; then
  if [[ -f server.key && -f server.key.plain ]] && diff server.key server.key.plain >/dev/null 2>&1; then
    touch server.key.passphrase
  else
    while :; do
      read -sp "Enter passphrase for server.key, or autogen by empty: " PASSPHRASE; echo
      if [[ "${#PASSPHRASE}" -lt 8 ]]; then
        echo_warn "passphrase is too short."
        if [[ -z $PASSPHRASE ]]; then
          PASSPHRASE=$(openssl rand -hex 32)
          echo "generated passphrase is $PASSPHRASE"
          break
        fi
      else
        break
      fi
    done
    echo_debug "make server.key.passphrase"
    echo "$PASSPHRASE" > server.key.passphrase
  fi
fi
PASSPHRASE=$(cat server.key.passphrase)

##秘密鍵を作成
if [[ ! -s server.key ]]; then
  echo_debug "make server.key"
  ##パスフレーズ無しでよければ以下
  #openssl genrsa -out server.key 2048
  ##パスフレーズを設定するばあいは以下、passphrase:*****
  autopass openssl genrsa -out server.key -aes256 2048
fi

##鍵ファイルの暗号化を解除する（これをしないと httpd start のときにパスを聞かれて止まってしまう）
if [[ server.key -nt server.key.plain ]]; then
  echo_debug "make server.key.plain"
  autopass openssl rsa -in server.key -out server.key.plain
fi

##ちゃんとした証明書を取る場合はcsrを作成してそれを使って証明証を申請した後、正式な証明書が来たらそれをserver.crtとして保存する
if [[ server.key -nt server.csr ]]; then
  echo_debug "make server.csr"
  autopass openssl req -sha1 -new -config config -key server.key -out server.csr
fi

##証明書作成
if [[ server.key -nt server.crt ]]; then
  echo_debug "make server.crt"
  ##自署証明書の場合は以下のコマンドでcrtを作成してしまえばよい
  autopass openssl req -sha1 -new -x509 -days $((10*365)) -config config -key server.key -out server.crt -set_serial `date +%s`
  echo_info "自動生成されたserver.crtはオレオレ証明書なので、server.csrをCAへ送って正規の証明書を取得して下さい。"
  echo_info "証明書が取得できたらserver.crtを差し替えて使います。"
  echo_info "更にその時 $0 を再度実行すればserver.inca.crtも更新します。"
  ##
  #cat <<EOF > server.crt
  #(正式に貰った証明書)
  #EOF

  ##中間証明書があればCAから取得して保存しておく
  touch server.inca.crt
fi

##証明書に対応した中間CA証明書を取得する
if [[ server.crt -nt server.inca.crt ]]; then
  echo_debug "make server.inca.crt"
  ./bin/collectInCACert.php server.crt > server.inca.crt
fi

##アプリケーションによってはDER形式の証明書を要求するものもあるのでそれも作っておく
if [[ server.crt -nt server.crt.der ]]; then
  echo_debug "make server.crt.der"
  openssl x509 -inform PEM -outform DER -in server.crt -out server.crt.der
fi

##アプリケーションによっては有用なのでキーと証明書をセットにしたpemファイルも作成しておく
if [[ server.key -nt server.key_and_crt.pem || server.crt -nt server.key_and_crt.pem ]]; then
  echo_debug "make server.key_and_crt.pem"
  cat server.key >  server.key_and_crt.pem
  cat server.crt >> server.key_and_crt.pem
fi
if [[ server.key -nt server.key_and_crt.pem.plain || server.crt -nt server.key_and_crt.pem.plain ]]; then
  echo_debug "make server.key_and_crt.pem.plain"
  cat server.key >  server.key_and_crt.pem.plain
  cat server.crt >> server.key_and_crt.pem.plain
fi

##サーバ証明書と中間証明書をセットにしたものも作っておくと良い
if [[ server.crt -nt server.crt_and_inca.pem || server.inca.crt -nt server.crt_and_inca.pem ]]; then
  echo_debug "make server.crt_and_inca.pem"
  cat server.crt      >  server.crt_and_inca.pem
  cat server.inca.crt >> server.crt_and_inca.pem
fi

## 互換性の為の一時的処置
if [[ -f server.cacert.crt && server.inca.crt -nt server.cacert.crt ]]; then
  echo_debug "make server.cacert.crt (DEPRECATED) -> server.inca.crt"
  ln -sfn server.inca.crt server.cacert.crt
fi

##パーミッション設定
chmod 644 server.*
chmod 600 server.key.*

##証明書情報の表示
echo_info "server.crt info is ..."
x509_startdate=$(date -d "$(openssl x509 -in server.crt -noout -startdate | perl -pe's/.*=//')" +'%Y-%m-%dT%H:%M:%S%z')
x509_enddate=$(date -d "$(openssl x509 -in server.crt -noout -enddate | perl -pe's/.*=//')" +'%Y-%m-%dT%H:%M:%S%z')
x509_CN=$(openssl x509 -in server.crt -noout -subject | perl -pe's/.*CN=([a-z0-9\*\.\-]+).*/$1/')
x509_SANs=($(openssl x509 -in server.crt -noout -text | grep -A1 "X509v3 Subject Alternative Name" | egrep -o 'DNS:[^,]+' | perl -pe's/.*://' | rev | sort | rev | uniq))
x509_Subjects=($(echo $x509_CN "${x509_SANs[@]}" | perl -pe's/\s/\n/g' | rev | sort | rev | uniq))
x509_issuer=$(openssl x509 -in server.crt -noout -issuer | perl -pe's/^issuer= *//')
echo "   Issuer: $x509_issuer"
echo "StartDate: $x509_startdate"
echo "  EndDate: $x509_enddate"
echo "SubjectCN: $x509_CN "
echo "     SANs: ${x509_SANs[@]}"
