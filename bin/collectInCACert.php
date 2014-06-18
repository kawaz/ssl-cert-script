#!/bin/env php
<?php
$file = (count($argv) == 2) ? $argv[1] : "php://stdin";
echo collectInCACert($file);

function collectInCACert($file, $depth=0, $subjectKeyIdentifier_verifier=null) {
  list($cert, $pem) = read_cert($file);
  $inca = "";
  $extensions = aget($cert, "extensions", []);
  $basicConstraints_CA = aget(text2hash(aget($extensions, "basicConstraints"), '/, */'), "CA");
  $subjectKeyIdentifier = aget($extensions, "subjectKeyIdentifier");
  $authorityKeyIdentifier_keyid = aget(text2hash(aget($extensions, "authorityKeyIdentifier")), "keyid");
  $authorityInfoAccess_CAIssuersURI = aget(text2hash(aget($extensions, "authorityInfoAccess")), "CA Issuers - URI");
  if(0) {//DEBUG
    echo "FILE: $file\n";
    echo "subjectKeyIdentifier: $subjectKeyIdentifier\n";
    echo "authorityKeyIdentifier: $authorityKeyIdentifier_keyid\n";
    $cert["purposes"] = array_map(function($a){return intval($a[0])." ".intval($a[1])." ".$a[2];},array_values($cert["purposes"]));
    echo json_encode($cert, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE)."\n";
  }
  //KeyIdentifierチェック(ついでにチェック)
  if(!empty($subjectKeyIdentifier_verifier) && $subjectKeyIdentifier != $subjectKeyIdentifier_verifier) {
    return; //ありえないことが起こっている
  }
  //親CAが無いので探索終了。RootCAは中間CAではないのでPEM出力もしない。
  if(empty($authorityKeyIdentifier_keyid)) {
    return $inca;
  }
  //中間CAのPEMを出力。中間CAを探しているのでdepth==0はスキップ。
  if($basicConstraints_CA == "TRUE" && 0 < $depth) {
    $inca .= $pem;
  }
  //親CAを辿ってPEMを連結する
  if(preg_match('/^https?:/', $authorityInfoAccess_CAIssuersURI)) {
    $inca .= collectInCACert($authorityInfoAccess_CAIssuersURI, $depth + 1, $authorityKeyIdentifier_keyid);
  }
  return $inca;
}

function aget($arr, $key, $default=null) {
  if(!is_array($arr)) {
    return $default;
  }
  return isset($arr[$key]) ? $arr[$key] : $default;
}

function text2hash($text, $spliter='/[\r\n]+/') {
  $hash = array();
  if(is_string($text)) {
    foreach(preg_split($spliter, $text) as $line) {
      $kv = preg_split('/:/', $line, 2);
      if(count($kv) == 2) {
        $hash[$kv[0]] = $kv[1];
      }
    }
  }
  return $hash;
}

function read_cert($file="php://stdin") {
  $pem = file_get_contents($file);
  $cert = openssl_x509_parse($pem);
  if($cert === false) {
    $pem = der2pem($pem);
    $cert = openssl_x509_parse($pem);
  }
  return array($cert, $pem);
}

function der2pem($der_data) {
  return "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der_data), 64, "\n") . "-----END CERTIFICATE-----\n";
}
