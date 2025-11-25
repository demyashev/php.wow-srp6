<?php

declare(strict_types=1);

namespace Tests;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use WOWSRP\SRP;

class SRPTest extends TestCase
{
    /**
     * @throws \ReflectionException
     */
    public function testSha1(): void
    {
        $class = new ReflectionClass(SRP::class);
        $method = $class->getMethod('hash');

        $this->assertEquals('a94a8fe5ccb19ba61c4c0873d391e987982fbbd3', $method->invokeArgs(new SRP(), ['test']));
        $this->assertEquals('0c3d7a19ac7c627290bf031ec3df76277b0f7f75', $method->invokeArgs(new SRP(), ["\x53\x51"]));
    }

    /**
     * @return void
     */
    public function testModule(): void
    {
        $prime = gmp_init(9, 10);
        $a = gmp_init(-2, 10);
        $b = gmp_init(3, 10);
        $pow = gmp_powm($a, $b, $prime);

        $this->assertEquals(1, gmp_intval($pow));
    }

    public function testCalculateX(): void
    {
        $srp = new SRP();

        $username = '00XD0QOSA9L8KMXC';
        $password = '43R4Z35TKBKFW8JI';

        $salt = hex2bin('CAC94AF32D817BA64B13F18FDEDEF92AD4ED7EF7AB0E19E9F2AE13C828AEAF57');
        $expected = hex2bin('E2F9A0F1E824006C98DA753448E743F7DAA1EAA1');

        $x = $srp->calculate_x($username, $password, $salt);

        $this->assertEquals($expected, $x);
    }

    public function testCalculatePasswordVerifier(): void
    {
        $srp = new SRP();

        $username = 'LF2BGFQIFQ3HZ1ZF';
        $password = 'MVRVMUJFWRA0IBVK';
        $salt = hex2bin('AFE5D28E925DBB3DAFED5D91ACA0928940E8FBFEF2D2A3CC154ADA0FE6ABEF6F');
        $expected = hex2bin('21B4153B0A938D0A69D28F2690CC3F79A99A13C40CACB525B3B79D4201EB33FF');

        $v = $srp->calculate_password_verifier($username, $password, $salt);

        $this->assertEquals($expected, $v);
    }

    public function testCalculateServerPublicKey(): void
    {
        $srp = new SRP();

        $password_verifier = hex2bin('870A98A3DA8CCAFE6B2F4B0C43A022A0C6CEF4374BA4A50CEBF3FACA60237DC4');
        $server_private_key = hex2bin('ACDCB7CB1DE67DB1D5E0A37DAE80068BCCE062AE0EDA0CBEADF560BCDAE6D6B9');
        $expected = hex2bin('85A204C987B68764FA69C523E32B940D1E1822B9E0F134FDC5086B1408A2BB43');

        $B = $srp->calculate_server_public_key($password_verifier, $server_private_key);

        $this->assertEquals($expected, $B);
    }

    public function testCalculateClientSKey(): void
    {
        $srp = new SRP();

        $server_public_key = hex2bin('626FE1E5F6F2B87DF7AF3B9AE7E50FCEB3E771ACAB9A39B99208A48A6B90BC8C');
        $client_private_key = hex2bin('473F4D6DD13D104DBA7952FFEDAAB73E41D9F39F0EC19AF2C4980B4BFEBAB051');
        $x = hex2bin('DCD6D4BAF581E7AA64E42AA3BDC2CD6D440C7A96');
        $u = hex2bin('9B88AB34F7A32BAAF9DBDBEF95DA59ACE2FBFD61');
        $expected = hex2bin('57998A49E9375A3C8FAD71893E212660C444D6CB0EE8922FC77E0C23C6016249');

        $S = $srp->calculate_client_s_key($client_private_key, $server_public_key, $x, $u);

        $this->assertEquals($expected, $S);
    }

    public function testCalculateServerSKey(): void
    {
        $srp = new SRP();

        $client_public_key = hex2bin('51CCDDFACF7F960EDF5030F09F0B033C0D08DB1E43FCBA3A92ABB4BE3535D1DB');
        $password_verifier = hex2bin('6FC7D4ACFCFFFDCF780EE9BBD17AE507FFCDF586F83B2C9AEE2198F195DB3AB5');
        $u = hex2bin('F9CEDDD82E776BEDB1A94852A9A7FFA4FCADD5DE');
        $server_private_key = hex2bin('A5DBBFCB4C7A1B7C3041CAC9DDBD36CD646F9FBABDAD66A019BCBB8FEDF2FAAE');
        $expected = hex2bin('3503B289A60D6DD59EBD6FD88DF24836833433E39048ECAFF7E887313554F85C');

        $S = $srp->calculate_server_s_key($client_public_key, $password_verifier, $u, $server_private_key);

        $this->assertEquals($expected, $S);
    }

    public function testCalculateU(): void
    {
        $srp = new SRP();

        $client_public_key = hex2bin('6FCEEEE7D40AAF0C7A08DFE1EFD3FCE80A152AA436CECB77FC06DAF9E9E5BDF3');
        $server_public_key = hex2bin('F8CD769BDE603FC8F48B9BE7C5BEAAA7BD597ABDBDAC1AEFCACF0EE13443A3B9');
        $expected = hex2bin('1309BD7851A1A505B95D6F60A8D884133458D24E');

        $u = $srp->calculate_u($client_public_key, $server_public_key);

        $this->assertEquals($expected, $u);
    }

    public function testCalculateInterleaved(): void
    {
        $srp = new SRP();

        $s_key = hex2bin('5199ED9CA852C03167A5BB7AB502D37603A281679B6D07E12E84C0F69C9AA84C');
        $expected = hex2bin('3612544A88232B29E510F7F2CA257C79D4172037CBE6359C6A3B718696F20D76DABDBACE0FF9FCEB');

        $key = $srp->calculate_interleaved($s_key);

        $this->assertEquals($expected, $key);
    }

    public function testCalculateServerProof(): void
    {
        $srp = new SRP();

        $client_public_key = hex2bin('BFD1AC65C8DAAAD88BF9DFF9AF8D1DCDF11DFD0C7E398EDCDF5DBBD08EFB39D3');
        $client_proof = hex2bin('7EBBC190D9AB2DC0CD891372CB30DF1ED35CDA1E');
        $session_key = hex2bin('4876E68F9FCCB6CA9BC9C9BCEBDB36F2358B6EAD0F17881D811891A9888E8E5B10E1162CE8B58293');
        $expected = hex2bin('269E3A3EF5DCD15944F043513BDA20D20FEBA2E0');

        $M2 = $srp->calculate_server_proof($client_public_key, $client_proof, $session_key);

        $this->assertEquals($expected, $M2);
    }

    public function testCalculateClientProof(): void
    {
        $srp = new SRP();

        $username = '7WG6SHZL33JMGPO4';
        $session_key = hex2bin('2F409C9AEC0FE203D3673202D57BEA19C931AACBD1FD75C539C34129BD70F83E37BFC0F99CD3A477');
        $client_public_key = hex2bin('0095FE039AFE5E1BADE9AC0CAEC3CB73D2D08BBF4CA8ADDBCDF0CE709ED5103F');
        $server_public_key = hex2bin('00B0C41F58CCE894CFB816FA72CA344C9FE2ED7CE799452ADBA7ABDCD26EAE75');
        $salt = hex2bin('00A4A09E0B5ACA438B8CD837D0816CA26043DBD1EAEF138EEF72DCF3F696D03D');
        $expected = hex2bin('7D07022B4064CCE633D679F61C6B212B6F8BC5C3');

        $M1 = $srp->calculate_client_proof($username, $session_key, $client_public_key, $server_public_key, $salt);

        $this->assertEquals($expected, $M1);
    }

    public function testCalculateClientPublicKey(): void
    {
        $srp = new SRP();

        $client_private_key = hex2bin('A47DD4CD70DA1B0EF7E1FA8C02DE68AF0CEFCC77ACA287FBC3ADCDE0E7B78FE7');
        $expected = hex2bin('7186DF27C1A309B5B26E293CD00ADD01E7037E09116089F26E810FD2D962BC42');

        $A = $srp->calculate_client_public_key($client_private_key);

        $this->assertEquals($expected, $A);
    }

    public function testCalculateReconnectProof(): void
    {
        $srp = new SRP();

        $username = 'JAOSIBOD9SMXPLVA';
        $client_data = hex2bin('502CA85BCF14D970889D54B0B8927513');
        $server_data = hex2bin('DA39A64A26BAA89F6757DFEF8C2E73A9');
        $session_key = hex2bin('8914CF403CF8BE3926A972B92235483E53220EE97F13A668049F8CB718A5D0DBF50CA126A344A20E');
        $expected = hex2bin('D24E63C064BA28036436ABAE166EA9647DD2353C');

        $reconnect = $srp->calculate_reconnect_proof($username, $client_data, $server_data, $session_key);

        $this->assertEquals($expected, $reconnect);
    }

    public function testEncrypt(): void
    {
        $srp = new SRP();

        $session_key = hex2bin('2EFEE7B0C177EBBDFF6676C56EFC2339BE9CAD14BF8B54BB5A86FBF81F6D424AA23CC9A3149FB175');
        $data = hex2bin('3d9ae196ef4f5be4df9ea8b9f4dd95fe68fe58b653cf1c2dbeaa0be167db9b27df32fd230f2eab9bd7e9b2f3fbf335d381ca');
        $expected = hex2bin('13777da3d109b912322a08841e3ff5bc92f4e98b77bb03997da999b22ae0b926a3b1e56580314b3932499ee11b9f7deb6915');

        $encrypted_data = $srp->encrypt($data, $session_key);

        $this->assertEquals($expected, $encrypted_data);
    }

    public function testDecrypt(): void
    {
        $srp = new SRP();

        $session_key = hex2bin('2EFEE7B0C177EBBDFF6676C56EFC2339BE9CAD14BF8B54BB5A86FBF81F6D424AA23CC9A3149FB175');
        $data = hex2bin('3d9ae196ef4f5be4df9ea8b9f4dd95fe68fe58b653cf1c2dbeaa0be167db9b27df32fd230f2eab9bd7e9b2f3fbf335d381ca');
        $expected = hex2bin('13a3a0059817e73404d97cd455159b50d40af74a22f719aacb6a9a2e991982c61a6f0285f880cc8512ec2ef1c98fa923512f');

        $unencrypted_data = $srp->decrypt($data, $session_key);

        $this->assertEquals($expected, $unencrypted_data);
    }

    public function testCalculateWorldServerProof()
    {
        $srp = new SRP();

        $username = 'HQO7EWULX09Z4RE4';
        $session_key = hex2bin('77295B4E6745E8833293E07650252D635D5E4B14D2A9DA4FB1AE22FB00131E42C2B2EE7BF0D4D185');
        $server_seed = hex2bin('2d0a01e2');
        $client_seed = hex2bin('a2ba5fb2');
        $expected = hex2bin('b26af9256f4bd20f0f11e2c786710542b92115bb');

        $world_server_proof = $srp->calculate_world_server_proof($username, $client_seed, $server_seed, $session_key);

        $this->assertEquals($expected, $world_server_proof);
    }

    public function testFinal(): void
    {
        $srp = new SRP();

        $username = 'username123';
        $password = 'password123';

        $request_c_to_s = '0113db66d21d66996cfab018b95e114d99abcbb3ec7e5c5e069cd3f89f76579c0e06fde5e7328f14e03615560990c0b04ab8619af0521f00afa66393866fc593bfa140aa50636e22cd0000';

        $client_s = 'cd226e6350aa40a1bf93c56f869363a6af001f52bb4d281f177c256c708b971f';
        $client_v = '0484a03b682d30a31310c1dd5eaa09ff5e1495cc442c31fbd2677d6b21e3e954';
        $client_a = '78f8d582b78880f7dd55a72cb2e89da25f9581f8610761e8f44736bb868216a4';
        $client_A = '314c456ad4785662771e766e6997f5b02a3b1069ac3fc8c31b28b859e0c88498';
        $client_u = '607cf9998143f60e7178fc3cc612827b373d1849';
        $client_x = 'bb452921bbc4c73c0a59a9bcdb50174ae05c78af';
        $client_S = '5199ed9ca852c03167a5bb7ab502d37603a281679b6d07e12e84c0f69c9aa84c';
        $client_K = '000a77d8c5bf85c06632b019774542dd0069b41d56fd8cd02a57ad89c2388221ae1a3b6974437bda';
        $client_M1= 'a42338aef407abfefeee8d744b9e7b08fba1c875';

        $request_s_to_c_s   = '1f978b706c257c171f284dbb521f00afa66393866fc593bfa140aa50636e22cd';
        $request_s_to_c_B   = '5d5afeccd4ac65b6211dcfc06f1ca144576b0f5151455f65d9e11bb1ebd3531b';
        $request_s_to_c_crc = 'baa31e99a00b2157fc373fb369cdd2f1';

        $server_s = 'CD226E6350AA40A1BF93C56F869363A6AF001F52BB4D281F177C256C708B971F';
        $server_v = '0484A03B682D30A31310C1DD5EAA09FF5E1495CC442C31FBD2677D6B21E3E954';
        $server_A = '314C456AD4785662771E766E6997F5B02A3B1069AC3FC8C31B28B859E0C88498';
        $server_b = 'C467F49EEF52D9FDE4BF452AC4EA10EB21B3C5';
        $server_B = '1B53D3EBB11BE1D9655F4551510F6B5744A11C6FC0CF1D21B665ACD4CCFE5A5D';
        $server_S = '5199ED9CA852C03167A5BB7AB502D37603A281679B6D07E12E84C0F69C9AA84C';
        $server_K = '3612544A88232B29E510F7F2CA257C79D4172037CBE6359C6A3B718696F20D76DABDBACE0FF9FCEB';
        $server_M2 ='7A0C28C344EE2652511F06D1820E56CB35A3FD12';

        // инициализируем из данных запроса
        $s = strrev(hex2bin($request_s_to_c_s));
        $B = strrev(hex2bin($request_s_to_c_B));

        // инициализируем из памяти сервера
        $a = hex2bin($client_a);
        $b = hex2bin($server_b);

        $A = $srp->calculate_client_public_key($a);

        $this->assertEquals($client_A, bin2hex($A));

        // серверная часть
        $v = $srp->calculate_password_verifier($username, $password, $s);
        $u = $srp->calculate_u($A, $B);
        $x = $srp->calculate_x($username, $password, $s);

        $this->assertEqualsIgnoringCase($server_v, bin2hex($v));


        $B = $srp->calculate_server_public_key($v, $b);

        $this->assertEqualsIgnoringCase($server_B, bin2hex($B));

        $s_S = $srp->calculate_server_s_key($A, $v, $u, $b);

        $this->assertEqualsIgnoringCase($server_S, bin2hex($s_S));

        $s_K = $srp->calculate_interleaved($s_S);

        $this->assertEqualsIgnoringCase(hex2bin($server_K), $s_K);

        $s_M1 = $srp->calculate_client_proof($username, $s_K, $A, $B, $s);

        $this->assertEqualsIgnoringCase($server_M2, bin2hex($s_M1));
        // сервераня часть -- сходится


        // клиентская часть
        $c_S = $srp->calculate_client_s_key($a, $B, $x, $u);

        $c_K = $srp->calculate_interleaved($c_S);

        $c_M1 = $srp->calculate_client_proof($username, $c_K, $A, $B, $s);

        $this->assertEquals(bin2hex($s_M1), bin2hex($c_M1));

        // клиентская часть -- сходится
    }
}