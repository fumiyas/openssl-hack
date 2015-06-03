##
## S/MIME sign/verify/encrypt/decrypt module by using openssl(1)
## Copyright (c) 2015 SATOH Fumiyasu @ OSS Technology Corp., Japan
## Copyright (c) 2002-2003 SATOH Fumiyasu, All rights reserved.
##
## Lisence: GNU General Public License version 2
## Date: 2003-04-14, since 2002-10-27
##

package smime;

use 5.006;
use strict;
use warnings;
use Carp;
use IO::File;
use IPC::Run;

use base qw(Exporter);
use vars qw(@EXPORT_OK);
@EXPORT_OK = qw(sign_smime verify_smime encrypt_smime decrypt_smime);


my $NON_US_ASCII = '[^\x01-\x7F]';
my $PATH_SEPARATOR = ($^O eq 'MSWin32') ? ';' : ':';
my $DIR_SEPARATOR = ($^O eq 'MSWin32') ? '\\' : '/';

## Options
## ======================================================================

my $OPENSSL = undef;
foreach my $dir (split(/$PATH_SEPARATOR/, $ENV{'PATH'}), '/usr/local/ssl/bin') {
    my $openssl_tmp = $dir . $DIR_SEPARATOR . 'openssl';
    if (-x $openssl_tmp) {
	$OPENSSL = $openssl_tmp;
	last;
    }
}
if (!defined($OPENSSL)) {
    carp "Cannot find openssl command in PATH";
    return undef;
}

my @SMIME = ($OPENSSL, 'smime');
my @SMIME_SIGN = (@SMIME, '-sign');
my @SMIME_VERIFY = (@SMIME, '-verify');
my @SMIME_ENCRYPT = (@SMIME, '-encrypt');
my @SMIME_DECRYPT = (@SMIME, '-decrypt');

my @CIPHER = qw(
    aes256 aes192 aes128
    camellia256 camellia192 camellia128
    des3
);
my $CIPHER_DEFAULT = 'aes128';

## ======================================================================

sub sign_smime
{
    my %arg = @_;
    my ($mess, $cert, $private, $pass, $from, $to, $subject) = @arg{qw(
	Message CertificateFile PrivateKeyFile PassPhraseFile From To Subject
    )};

    if (!defined($mess) or !defined($private) or !defined($cert)) {
	carp 'Message, PrivateKeyFile and CertificateFile required';
	return undef;
    }
    ## $mess must be US-ASCII (7bit data)
    if ($mess =~ /$NON_US_ASCII/) {
	carp 'Message has non-US-ASCII character (0x00 or >0x7F)';
	return undef;
    }
    if (!-r $private) {
	carp 'Cannot read PrivateKeyFile';
	return undef;
    }
    if (!-r $cert) {
	carp 'Cannot read CertificateFile';
	return undef;
    }

    ## The `openssl smime -sign` requires input that must be rewindable.
    ## Create temporary file for message...
    my $fh_mess = IO::File->new_tmpfile();
    if (!defined($fh_mess)) {
	carp "Cannot create temporary file for Message: $!";
	return undef;
    }
    $fh_mess->print($mess);
    $fh_mess->seek(0, SEEK_SET);

    my @smime = (@SMIME_SIGN, '-inkey', $private, '-signer', $cert);
    push(@smime, '-passin', "file:$pass") if (defined($pass));
    push(@smime, '-from', $from) if (defined($from));
    push(@smime, '-to', $to) if (defined($to));
    push(@smime, '-subject', $subject) if (defined($subject));

    my $out = my $err = '';
    my @cmd = (\@smime, '<', $fh_mess, '>', \$out, '2>', \$err);
    eval {
	IPC::Run::run(@cmd);
    };
    if ($@) {
	warn "openssl: $@";
	carp 'Signing message by S/MIME failed';
	return undef;
    } elsif ($? != 0) {
	warn "openssl: $err";
	carp 'Signing message by S/MIME failed';
	return undef;
    }

    return $out;
}

sub verify_smime
{
    my %arg = @_;
    my ($mess, $cacert) = @arg{qw(
	Message CACertificateFile
    )};

    if (!defined($mess) or !defined($cacert)) {
	carp 'Message and CACertificateFile required';
	return undef;
    }
    if (!-r $cacert) {
	carp 'Cannot read CACertificateFile';
	return undef;
    }

    my @smime = (@SMIME_VERIFY, '-CAfile', $cacert);

    my $out = my $err = '';
    my @cmd = (\@smime, '<', \$mess, '>', \$out, '2>', \$err);
    eval {
	IPC::Run::run(@cmd);
    };
    if ($@) {
	warn "openssl: $@";
	carp 'Verifying signature by S/MIME failed';
	return undef;
    } elsif ($? != 0) {
	warn "openssl: $err";
	carp 'Verifying signature by S/MIME failed';
	return undef;
    }

    return $out;
}

sub encrypt_smime
{
    my %arg = @_;
    my ($mess, $cert, $cipher, $from, $to, $subject) = @arg{qw(
	Message CertificateFile Cipher From To Subject
    )};

    if (!defined($mess) or !defined($cert)) {
	carp 'Message and CertificateFile required';
	return undef;
    }
    ## $mess must be US-ASCII (7bit data)
    if ($mess =~ /$NON_US_ASCII/) {
	carp 'Message has non-US-ASCII character (0x00 or >0x7F)';
	return undef;
    }
    if (!-r $cert) {
	carp 'Cannot read CertificateFile';
	return undef;
    }
    if (!defined($cipher)) {
	$cipher = $CIPHER_DEFAULT;
    }
    if (!grep($cipher eq $_, @CIPHER)) {
	carp 'Unsupported cipher name';
	return undef;
    }

    my @smime = (@SMIME_ENCRYPT, "-$cipher");
    push(@smime, '-from', $from) if (defined($from));
    push(@smime, '-to', $to) if (defined($to));
    push(@smime, '-subject', $subject) if (defined($subject));
    push(@smime, $cert);

    my $out = my $err = '';
    my @cmd = (\@smime, '<', \$mess, '>', \$out, '2>', \$err);
    eval {
	IPC::Run::run(@cmd);
    };
    if ($@) {
	warn "openssl: $@";
	carp 'Encrypting message by S/MIME failed';
	return undef;
    } elsif ($? != 0) {
	warn "openssl: $err";
	carp 'Encrypting message by S/MIME failed';
	return undef;
    }

    return $out;
}

sub decrypt_smime
{
    my %arg = @_;
    my ($mess, $cert, $private, $pass) = @arg{qw(
	Message CertificateFile PrivateKeyFile PassPhraseFile
    )};

    if (!defined($mess) or !defined($cert) or !defined($private)) {
	carp 'Message, CertificateFile and PrivateKeyFile required';
	return undef;
    }
    if (!-r $cert) {
	carp 'Cannot read CertificateFile';
	return undef;
    }
    if (!-r $private) {
	carp 'Cannot read PrivateKeyFile';
	return undef;
    }

    my @smime = (@SMIME_DECRYPT, '-inkey', $private, '-recip', $cert);
    push(@smime, '-passin', "file:$pass") if (defined($pass));

    my $out = my $err = '';
    my @cmd = (\@smime, '<', \$mess, '>', \$out, '2>', \$err);
    eval {
	IPC::Run::run(@cmd);
    };
    if ($@) {
	warn "openssl: $@";
	carp 'Decrypting message by S/MIME failed';
	return undef;
    } elsif ($? != 0) {
	warn "openssl: $err";
	carp 'Decrypting message by S/MIME failed';
	return undef;
    }

    return $out;
}

## For testing this module, you need to execute following command:
##	openssl req -new -x509 -nodes -keyout private.pem > cert.pem
##	perl -we 'use strict;use smime; smime::_test()'
sub _test
{
    my $plain = "original plain text\n";

    print "-- original\n";
    print $plain;
    my $signed = sign_smime(
	Message =>		$plain,
	PrivateKeyFile =>	'private.pem',
	CertificateFile =>	'cert.pem',
	To =>			'test@example.com',
    );
    print "-- original -> S/MIME signed\n";
    print $signed;
    print "-- original -> S/MIME signed -> S/MIME verified\n";
    print verify_smime(
	Message =>		$signed,
	CACertificateFile =>	'cert.pem',
    );

    print "\n\n";

    print "-- original\n";
    print $plain;
    my $crypted = encrypt_smime(
	Message =>		$plain,
	CertificateFile =>	'cert.pem',
	To =>			'test@example.com',
    );
    print "-- original -> S/MIME encrypted\n";
    print $crypted;
    print "-- original -> S/MIME encrypted -> S/MIME decrypted\n";
    print decrypt_smime(
	Message =>		$crypted,
	PrivateKeyFile =>	'private.pem',
	CertificateFile =>	'cert.pem',
    );
}

1;

__END__

=head1 名前

smime - OpenSSL の openssl コマンドを利用した S/MIME ライブラリ

=head1 概要

暗号化:

    use smime;
    my $crypted_mess = smime::encrypt_smime(
	Message => $plain_mess,
	CertificateFile => 'recipient-cert.pem'
    );
    die 'Encrypting failed' if (!defined($crypted_mess));

復号化:

    use smime;
    my $plain_mess = smime::decrypt_smime(
	Message => $crypted_mess,
	PrivateKeyFile => 'my-private.pem',
	CertificateFile => 'my-cert.pem'
    );
    die 'Decrypting failed' if (!defined($plain_mess));

=head1 解説

smime は OpenSSL の openssl コマンドを利用した S/MIME ライブラリで、
メールメッセージを S/MIME 形式で署名/署名確認/暗号化/復号化するための
サブルーチンを提供します。

openssl コマンドは、環境変数 PATH に設定されているパスの何れかに
置かれていなければなりません。
また、別途 IPC::Run モジュールが必要です。
本モジュールは、OpenSSL 0.9.6g の openssl コマンドと、
IPC::Run 0.74 にて動作確認を行いました。

=head1 鍵と証明書の作成

S/MIME の各処理を行うには、公開鍵方式の鍵と証明書が必要になります。
この節では、openssl コマンドを利用して、秘密鍵と自己署名の証明書
(秘密鍵に対応する公開鍵が含まれる)
を作成する例を紹介します。
メッセージの暗号化/復号化だけを行い、
詐称/改竄を防ぐための署名/署名確認を行わないのであれば、
自己署名の証明書で十分です。

次の例は、秘密鍵を private.pem に、
公開鍵が含まれる自己署名の証明書を cert.pem に生成します。

    openssl req -new -x509 -nodes -keyout private.pem > cert.pem

引数の意味は次の通りです。
詳細は、OpenSSL 関係の文書や関連資料を参照してください。

=over 4

=item req

証明書発行要求関連の処理を実行するサブコマンド

=item -new

新規作成

=item -x509

自己署名の証明書を作成

=item -nodes

秘密鍵を DES などで暗号化しない

=item -keyout

秘密鍵の出力先指定

=back

=head1 暗号化

C<smime::encrypt_smime> を利用して、メールメッセージから
S/MIME 形式の暗号化メッセージを生成することができます。

    my $crypted_mess = smime::encrypt_smime(
	Message => $plain_mess,
	CertificateFile => 'recipient-cert.pem',
    );

=over 4

=item Message

暗号対象のメールのメッセージを指定します。
メッセージは、RFC 2822 に従った適切な形式でなければなりません。
たとえば、メッセージに日本語が含まれている場合、
文字コードは ISO-2022-JP (いわゆる JIS コード)
に変換されていなければなりません。

=item CertificateFile

送信相手の証明書が含まれているファイルの名前を指定します。

=item 戻り値

暗号化に成功すると、暗号化されたメッセージを返します。
暗号化に失敗すると、標準エラー出力に情報を表示して C<undef> を返します。

以下は、C<smime::encrypt_smime> によって生成された
S/MIME 暗号化メッセージの例です。
これに必要なヘッダーを追加して送信することになります。

    MIME-Version: 1.0
    Content-Disposition: attachment; filename="smime.p7m"
    Content-Type: application/x-pkcs7-mime; name="smime.p7m"
    Content-Transfer-Encoding: base64

    MIIBOgYJKoZIhvcNAQcDoIIBKzCCAScCAQAxgeQwgeECAQAwSjBFMQswCQYDVQQG
    EwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lk
    Z2l0cyBQdHkgTHRkAgEAMA0GCSqGSIb3DQEBAQUABIGAS3+/3nNEkGHAt31Airwj
    0Hd8VVMsbVzvFqZZKho4GSDiNpJEu4TOQvz/JUbzkZ+CrMJb41tyOARYT6sC+Aqe
    k4vmnUaIhTNRhr02LQD6iiIfGI9CkXyXtzFqKe+sucO0sKtVKQ/XmD1xgmnQ7GR4
    bK6XCd7RO1mfrFVd9dKGL18wOwYJKoZIhvcNAQcBMBQGCCqGSIb3DQMHBAhYMjJ2
    4fieN4AYM2TQwYqikeFT8lxJ4NSVZ0Chiqt9/xc0

=back

=head1 復号化

C<smime::decrypt_smime> を利用して、S/MIME 形式の暗号化メールメッセージを
元のメッセージに戻すことができます。

    my $plain_mess = smime::encrypt_smime(
	Message => $crypted_mess,
	PrivateKeyFile => 'my-privatge.pem',
	CertificateFile => 'my-cert.pem',
    );

=over 4

=item Message

S/MIME 形式の暗号化されたメールメッセージを指定します。

=item PrivateKeyFile

自分の所有する秘密鍵
(暗号化時に使用された証明書に対応するもの)
が含まれているファイルの名前を指定します。

=item CertificateFile

自分の所有する証明書
(暗号化時に使用されたもの)
が含まれているファイルの名前を指定します。

=item PassPhraseFile

秘密鍵の暗号を解くためのパスフレーズが含まれているファイルを指定します。
秘密鍵を暗号化せずに保存しているなら指定する必要はありません。

=item 戻り値

復号化に成功すると、復号化されたメッセージを返します。
復号化に失敗すると、標準エラー出力に情報を表示して C<undef> を返します。

=back

=head1 参照

=item L<http://www.atmarkit.co.jp/fsecurity/special/04smime/smime01.html>

=item L<http://cvs.cacanet.org/fsc/smime/>

=item L<http://www.tanu.org/~sakane/doc/public/howto-ssleay.html>

=cut
