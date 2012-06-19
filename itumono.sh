#!/bin/sh

##ユーティリティ関数定義
function echo_red()     { echo -e "\033[0;31m$@\033[0m"; }
function echo_green()   { echo -e "\033[0;32m$@\033[0m"; }
function echo_yellow()  { echo -e "\033[0;33m$@\033[0m"; }
function echo_blue()    { echo -e "\033[0;34m$@\033[0m"; }
function echo_magenta() { echo -e "\033[0;35m$@\033[0m"; }
function echo_cyan()    { echo -e "\033[0;36m$@\033[0m"; }
function echo_debug()   { echo_cyan "$@"; }
function echo_info()    { echo_green "$@"; }
function echo_warn()    { echo_magenta "$@"; }
function echo_error()   { echo_red "$@"; }

##configファイルチェック
if [ ! -f config ]; then
  echo_debug "make config"
  cp "`dirname "$0"`"/config.sample config
fi
if (diff -bB config config.sample >/dev/null 2>&1); then
  echo_error "Please edit config."
  exit 1
fi

##パスフレーズ自動化陽関数定義
function autopass() {
  if [ -x "`which expect 2>/dev/null`" ]; then
    # expectが使えるならパスフレーズを自動入力する
    expect -c "
      spawn $@
      expect {
        \"Enter pass phrase for \" {
          send \"$PASSPHRASE\n\"
          exp_continue
        }
      }
    "
  else
    # expectが無いので普通に実行する
    echo_warn "expectをインストールしたらパスフレーズの入力が自動化されるお勧め"
    "$@"
  fi
}

##パスフレーズを保存
if [ ! -f server.passphrase ]; then
  while :; do
    read -sp "Enter pass phrase for server.key: " PASSPHRASE; echo
    if [ "${#PASSPHRASE}" -lt 8 ]; then
      echo_warn "pass phrase is too short."
    else
      break
    fi
  done
  echo_debug "make server.passphrase"
  echo "$PASSPHRASE" > server.passphrase
fi
PASSPHRASE="`cat server.passphrase`"

##秘密鍵を作成
if [ ! -s server.key ]; then
  echo_debug "make server.key"
  ##パスフレーズ無しでよければ以下
  #openssl genrsa -out server.key 2048
  ##パスフレーズを設定するばあいは以下、passphrase:*****
  autopass openssl genrsa -out server.key -aes128 2048
fi

##鍵ファイルの暗号化を解除する（これをしないと httpd start のときにパスを聞かれて止まってしまう）
if [ server.key -nt server.key.plain ]; then
  echo_debug "make server.key.plain"
  autopass openssl rsa -in server.key -out server.key.plain
fi

##ちゃんとした証明書を取る場合はcsrを作成してそれを使って証明証を申請した後、正式な証明書が来たらそれをserver.crtとして保存する
if [ server.key -nt server.csr ]; then
  echo_debug "make server.csr"
  autopass openssl req -sha1 -new -config config -key server.key -out server.csr
fi

##証明書作成
if [ server.key -nt server.crt ]; then
  echo_debug "make server.crt"
  ##自署証明書の場合は以下のコマンドでcrtを作成してしまえばよい
  autopass openssl req -sha1 -new -x509 -days $((10*365)) -config config -key server.key -out server.crt -set_serial `date +%s`
  echo_info "自動生成されたserver.crtはオレオレ証明書なので、server.csrをCAへ送って正規の証明書を取得して下さい。"
  echo_info "証明書が取得できたらserver.crtを差し替えて使います。"
  echo_info "更にその時 $0 を再度実行すればserver.cacert.crtも更新します。"
  ##
  #cat <<EOF > server.crt
  #(正式に貰った証明書)
  #EOF

  ##中間証明書があればCAから取得して保存しておく
  touch server.cacert.crt
fi

##証明書に対応した中間CA証明書を取得する
if [ server.crt -nt server.cacert.crt ]; then
  IssuerCN="`openssl x509 -in server.crt -text | egrep '^ +Issuer:.* CN=[^,]+' | perl -pe's/.* CN=//;s/,.*//'`"
  case "$IssuerCN" in
    "StartCom Class 1 "*)
      CaCertURL_DER="http://www.startssl.com/certs/sub.class1.server.ca.crt"
      ;;
    "StartCom Class 2 "*)
      CaCertURL_DER="http://www.startssl.com/certs/sub.class2.server.ca.crt"
      ;;
    "StartCom Class 3 "*)
      CaCertURL_DER="http://www.startssl.com/certs/sub.class3.server.ca.crt"
      ;;
  esac
  if [ "x$CaCertURL_PEM" != "x" ]; then
    echo_debug "make server.cacert.crt"
    curl "$CaCertURL_PEM" -o server.cacert.crt
    echo_debug "make server.cacert.crt.der"
    openssl x509 -in server.cacert.crt -outform der -out server.cacert.crt.der
  elif [ "x$CaCertURL_DER" != "x" ]; then
    echo_debug "make server.cacert.crt.der"
    curl "$CaCertURL_DER" -o server.cacert.crt.der
    echo_debug "make server.cacert.crt"
    openssl x509 -inform der -in server.cacert.crt.der -out server.cacert.crt
  fi
fi


##アプリケーションによってはDER形式の証明書を要求するものもあるのでそれも作っておく
if [ server.crt -nt server.crt.der ]; then
  echo_debug "make server.crt.der"
  openssl x509 -inform PEM -outform DER -in server.crt -out server.crt.der
fi

##アプリケーションによっては有用なのでキーと証明書をセットにしたpemファイルも作成しておく
if [ server.key -nt server.key_and_crt.pem -o server.crt -nt server.key_and_crt.pem ]; then
  echo_debug "make server.key_and_crt.pem"
  cat server.key >  server.key_and_crt.pem
  cat server.crt >> server.key_and_crt.pem
fi
if [ server.key -nt server.key_and_crt.pem.plain -o server.crt -nt server.key_and_crt.pem.plain ]; then
  echo_debug "make server.key_and_crt.pem.plain"
  cat server.key >  server.key_and_crt.pem.plain
  cat server.crt >> server.key_and_crt.pem.plain
fi

##サーバ証明書と中間証明書をセットにしたものも作っておくと良い
if [ server.crt -nt server.crt_and_cacert.pem -o server.cacert.crt -nt server.crt_and_cacert.pem ]; then
  echo_debug "make server.crt_and_cacert.pem"
  cat server.crt        >  server.crt_and_cacert.pem
  cat server.cacert.crt >> server.crt_and_cacert.pem
fi


##パーミッション設定
chmod 600 server.*