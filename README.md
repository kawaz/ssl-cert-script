ssl-cert-script
===============

SSL証明書の作成用のスクリプト


#サーバーキーの取得手順

まず`server.csr`を作る。

    bash itumono.sh
    vim config
    bash itumono.sh

`server.csr`が作られるのでこれをCAのサイトにコピペして証明書発行の手続きを行う。
CAによって差があるが数分から数日のうちにcrtが送られてくるので、`server.crt`に上書き保存して、再度`sh itumono.sh`を実行すると中間CAの証明書を自動取得して`server.inca.crt`が更新される。
サーバアプリにはキー、SSL証明書、中間CA証明書として、`server.key.plain`と`server.crt`と`server.inca.crt`を指定して使う。

#サーバーキーの利用例 

##node.js の例

    var fs = require('fs')
      , https = require('https')
      , opts =
        { key: fs.readFileSync('server.key.plain', 'utf8')
        , cert: fs.readFileSync('server.crt', 'utf8')
        , ca: [fs.readFileSync('server.inca.crt', 'utf8')]
        }
      , server = https.createServer(opts, function(req, res){
          res.end("Hello SSL");
        }).listen(33333);
