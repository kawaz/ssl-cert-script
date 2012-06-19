ssl-cert-script
===============

SSL証明書の作成用のスクリプト


まず`server.csr`を作る。

    sh itumono.sh
    vim config
    sh itumono.sh

`server.csr`が作られるのでこれをCAのサイトにコピペして証明書発行の手続きを行う。
CAによって差があるが数分から数日のうちにcrtが送られてくるので、`server.crt`に上書き保存して、再度`sh itumono.sh`を実行する。
必要があれば取得した証明書に対応した中間CAの証明書を`server.cacert.crt`に保存しておく。
サーバアプリにはキー、SSL証明書、中間CA証明書として、`server.key.plain`と`server.crt`と`server.cacert.crt`を指定して使う。

    // node.js の例
    var https = require('https');
    var server = https.createServer(
      { key: fs.readFileSync('server.key.plain', 'utf8'),
        cert: fs.readFileSync('server.crt', 'utf8'),
        ca: [fs.readFileSync('server.cacert.crt', 'utf8')]
      });

