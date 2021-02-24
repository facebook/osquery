/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>
#include <osquery/utils/windows/shellitem.h>

#include <string>

namespace osquery {

class ShellitemTests : public testing::Test {};

TEST_F(ShellitemTests, test_shellitem_fileentry) {
  std::string data =
      "56003100000000000000000010006F73717565727900400009000400EFBE000000000000"
      "00002E00000000000000000000000000000000000000000000000000000000006F007300"
      "71007500650072007900000016000000";
  auto file_entry = fileEntry(data);
  ASSERT_TRUE(file_entry.path == "osquery");
  ASSERT_TRUE(file_entry.mft_entry == 0LL);
  ASSERT_TRUE(file_entry.dos_created == 0LL);
  ASSERT_TRUE(file_entry.dos_modified == 0LL);
  ASSERT_TRUE(file_entry.dos_accessed == 0LL);
  ASSERT_TRUE(file_entry.mft_sequence == 0LL);
}

TEST_F(ShellitemTests, test_shellitem_ftpserver) {
  std::string data =
      "560061034C00030100000400000012122B8B7BFBD601FFFFFFFF00000000000000000000"
      "000015000000140000007370656564746573742E74656C65322E6E657400040000000000"
      "00000400000000000000667470000000";
  std::vector<std::string> ftp_data = ftpItem(data);
  ASSERT_TRUE(ftp_data[1] == "speedtest.tele2.net");
  ASSERT_TRUE(ftp_data[0] == "12122B8B7BFBD601");
}

TEST_F(ShellitemTests, test_shellitem_zipcontent) {
  std::string data =
      "86007E0043003A0000000000000000000000000000000000000000000000000010000000"
      "4E002F0041000000000000000000000000000000010000000000000004E3CB1700000000"
      "0100000000000000FFFF000011000000000000004C004900450046002D0030002E003100"
      "30002E0031002D00770069006E0036003400000000006D6265720000";
  auto name = zipContentItem(data);
  ASSERT_TRUE(name == "LIEF-0.10.1-win64");
}

TEST_F(ShellitemTests, test_shellitem_mtpdevice) {
  std::string data =
      "9C050000960505203110030000001A0020000080AF38060000000000000000000000B602"
      "00001800000019000000150000000700000049006E007400650072006E0061006C002000"
      "7300680061007200650064002000730074006F0072006100670065000000530049004400"
      "2D007B00310030003000300031002C002C00320036003700320030003800320039003400"
      "340030007D000000470065006E0065007200690063002000680069006500720061007200"
      "630068006900630061006C0000007B00450046003200310030003700440035002D004100"
      "3500320041002D0034003200340033002D0041003200360042002D003600320044003400"
      "310037003600440037003600300033007D0000007B003400410044003200430038003500"
      "45002D0035004500320044002D0034003500450035002D0038003800360034002D003400"
      "460032003200390045003300430036004300460030007D0000007B003100410033003300"
      "46003700450034002D0041004600310033002D0034003800460035002D00390039003400"
      "45002D003700370033003600390044004600450030003400410033007D0000007B003900"
      "32003600310042003000330043002D0033004400370038002D0034003500310039002D00"
      "38003500450033002D003000320043003500450031004600350030004200420039007D00"
      "00007B00360038003000410044004600350032002D0039003500300041002D0034003000"
      "340031002D0039004200340031002D003600350045003300390033003600340038003100"
      "350035007D0000007B00320038004400380044003300310045002D003200340039004300"
      "2D0034003500340045002D0041004100420043002D003300340038003800330031003600"
      "380045003600330034007D0000007B00320037004500320045003300390032002D004100"
      "3100310031002D0034003800450030002D0041004200300043002D004500310037003700"
      "300035004100300035004600380035007D0000000D00000003D5150C17D0CE4790167B3F"
      "978721CC0F0000007A05A301D674804EBEA7DC4C212CE50A020000001300000003000000"
      "7A05A301D674804EBEA7DC4C212CE50A030000001F0000002A000000470065006E006500"
      "7200690063002000680069006500720061007200630068006900630061006C0000007A05"
      "A301D674804EBEA7DC4C212CE50A0B00000013000000000000007A05A301D674804EBEA7"
      "DC4C212CE50A04000000150000000080AF38060000007A05A301D674804EBEA7DC4C212C"
      "E50A05000000150000000070F58B050000007A05A301D674804EBEA7DC4C212CE50A0600"
      "00001500000000000040000000007A05A301D674804EBEA7DC4C212CE50A070000001F00"
      "00003000000049006E007400650072006E0061006C002000730068006100720065006400"
      "2000730074006F00720061006700650000000D496BEFD85C7A43AFFCDA8B60EE4A3C0500"
      "00001F000000320000005300490044002D007B00310030003000300031002C002C003200"
      "36003700320030003800320039003400340030007D0000000D496BEFD85C7A43AFFCDA8B"
      "60EE4A3C040000001F0000003000000049006E007400650072006E0061006C0020007300"
      "680061007200650064002000730074006F00720061006700650000007A05A301D674804E"
      "BEA7DC4C212CE50A080000001F0000000200000000000D496BEFD85C7A43AFFCDA8B60EE"
      "4A3C0600000048000000000001306CAE044898BAC57B46965FE70D496BEFD85C7A43AFFC"
      "DA8B60EE4A3C1A0000000B00000000000D496BEFD85C7A43AFFCDA8B60EE4A3C07000000"
      "480000006001ED99FF17444C9D981D7A6F941921932D058FCAABC54FA5ACB01DF4DBE598"
      "0200000048000000BC5BF023DE152A4CA55BA9AF5CE412EF0D496BEFD85C7A43AFFCDA8B"
      "60EE4A3C170000001F0000000E000000730031003000300030003100000000000000";
  auto name = mtpDevice(data);
  ASSERT_TRUE(name == "Internal shared storage");
}

TEST_F(ShellitemTests, test_shellitem_rootentry) {
  std::string data = "3A001F44471A0359723FA74489C55595FE6B30EE260001002600EFBE100000002A4B9884B387D50168891281D387D501BF5E6881D387D50114000000";
  auto name = rootFolderItem(data);
  ASSERT_TRUE(name == "59031A47-3F72-44A7-89C5-5595FE6B30EE");
}

TEST_F(ShellitemTests, test_shellitem_driveletterentry) {
  std::string data = "19002F433A5C000000000000000000000000000000000000000000";
  auto name = driveLetterItem(data);
  ASSERT_TRUE(name == "C:\\");
}

TEST_F(ShellitemTests, test_shellitem_mtpfolder) {
  std::string data =
      "0E030000080306201907FB000000020020000000000000000000000000000000000080FD"
      "D223D4F9D40192E3E22711A1E048AB0CE17705A05F85400200000D0000000D0000002700"
      "0000730075007000650072007400750078006B0061007200740000007300750070006500"
      "72007400750078006B0061007200740000007B0030003000300032004600410042003200"
      "2D0030003000300031002D0030003000300031002D0030003000300030002D0030003000"
      "30003000300030003000300030003000300030007D0000000D00000003D5150C17D0CE47"
      "90167B3F978721CC0C0000000D496BEFD85C7A43AFFCDA8B60EE4A3C020000001F000000"
      "0E0000006F00320046004100420032000000ABFDD4FB7D987747B3F9726185A9312B0200"
      "00001F0000000200000000000D496BEFD85C7A43AFFCDA8B60EE4A3C1300000007000000"
      "A2A702F34B47E5400D496BEFD85C7A43AFFCDA8B60EE4A3C060000004800000000000130"
      "6CAE044898BAC57B46965FE70D496BEFD85C7A43AFFCDA8B60EE4A3C0700000048000000"
      "92E3E22711A1E048AB0CE17705A05F850D496BEFD85C7A43AFFCDA8B60EE4A3C04000000"
      "1F0000001A000000730075007000650072007400750078006B0061007200740000000D49"
      "6BEFD85C7A43AFFCDA8B60EE4A3C170000001F0000000E00000073003100300030003000"
      "310000000D496BEFD85C7A43AFFCDA8B60EE4A3C050000001F0000004E0000007B003000"
      "30003000320046004100420032002D0030003000300031002D0030003000300031002D00"
      "30003000300030002D003000300030003000300030003000300030003000300030007D00"
      "00000D496BEFD85C7A43AFFCDA8B60EE4A3C1A0000000B000000FFFF5850544DCE4F7845"
      "95C88698A9BC0F4903DC00001200000000005850544DCE4F784595C88698A9BC0F494EDC"
      "00001F000000200000003200300031003700310031003200370054003000360035003300"
      "3300330000000D496BEFD85C7A43AFFCDA8B60EE4A3C0C0000001F0000001A0000007300"
      "75007000650072007400750078006B00610072007400000000000000";
  auto name = mtpFolder(data);
  ASSERT_TRUE(name == "supertuxkart");
}

TEST_F(ShellitemTests, test_shellitem_mtproot) {
  std::string data =
      "6E012E004801062031080300000000000000030000006E00000001000000090000005200"
      "000000004E00650078007500730020003500580000005C005C003F005C00750073006200"
      "23007600690064005F00310038006400310026007000690064005F003400650065003100"
      "230030003200350061006300650063003600320064003400380063003200340038002300"
      "7B00360061006300320037003800370038002D0061003600660061002D00340031003500"
      "35002D0062006100380035002D0066003900380066003400390031006400340066003300"
      "33007D0000000D00000003D5150C17D0CE4790167B3F978721CC020000009A97D42643E6"
      "26469E2B736DC0C92FDC0C0000001F000000120000004E00650078007500730020003500"
      "58000000932D058FCAABC54FA5ACB01DF4DBE59802000000480000006B46EA08A4E33643"
      "A1F3A44D2B5C438C0000741A595E96DFD3488D671733BCEE28BA3C6D783575B0B94988DD"
      "029876E11C010000";
  auto name = mtpRoot(data);
  ASSERT_TRUE(name == "Nexus 5X");
}

TEST_F(ShellitemTests, test_shellitem_controlpanelcategoryitem) {
  std::string data = "0C0001008421DE39050000000000";
  auto name = controlPanelCategoryItem(data);
  ASSERT_TRUE(name == "System and Security");
}

TEST_F(ShellitemTests, test_shellitem_controlpanelitem) {
  std::string data =
      "1E007180000000000000000000006ABE817B2BCE7646A29EEB907A5126C50000";
  auto name = controlPanelItem(data);
  ASSERT_TRUE(name == "7B81BE6A-CE2B-4676-A29E-EB907A5126C5");
}

TEST_F(ShellitemTests, test_shellitem_variableftp) {
  std::string data =
      "3E0000000000050003001000000000700A00000000000018389483FBD601550700000000"
      "000075706C6F61640000750070006C006F0061006400000000000000";
  auto name = variableFtp(data);
  ASSERT_TRUE(name == "upload");
}

TEST_F(ShellitemTests, test_shellitem_variableguid) {
  std::string data =
      "200000001A00EEBBFE23000010003ACCBFB42CDB4C42B0297FE99A87C64100000000";
  auto name = variableGuid(data);
  ASSERT_TRUE(name == "B4BFCC3A-DB2C-424C-B029-7FE99A87C641");
}

TEST_F(ShellitemTests, test_shellitem_propertyviewdrive) {
  std::string data =
      "55001F002F0010B7A6F519002F443A5C0000000000000000000000000000000000000000"
      "0000000000000000000000000000000000741A595E96DFD3488D671733BCEE28BA772CFB"
      "F52F0E164AA3813E560C68BC830000";
  auto name = propertyViewDrive(data);
  ASSERT_TRUE(name == "D:\\");
}

TEST_F(ShellitemTests, test_shellitem_propertystore) {
  std::string data = "100100000A01BBAF933BFC000400000000002D000000315350537343E50ABE43AD4F85E469DC8633986E110000000B000000000B000000FFFF000000000000450000003153505330F125B7EF471A10A5F102608C9EEBAC290000000A000000001F0000000C00000076006D0077006100720065002D0068006F00730074000000000000005900000031535053A66A63283D95D211B5D600C04FD918D03D0000001F000000001F0000001600000056004D0077006100720065002000530068006100720065006400200046006F006C0064006500720073000000000000002D000000315350533AA4BDDEB337834391E74498DA2995AB1100000003000000001300000000000000000000000000000000000000";
  std::vector<size_t> wps_list;
  size_t wps = data.find("31535053");
  while (wps != std::string::npos) {
    wps_list.push_back(wps);
    wps = data.find("31535053", wps + 1);
  }
  auto name = propertyStore(data, wps_list);
  ASSERT_TRUE(name == "vmware-host");
}

TEST_F(ShellitemTests, test_shellitem_networkshare) {
  std::string data = "3A00C301815C5C766D776172652D686F73745C53686172656420466F6C6465727300564D776172652053686172656420466F6C64657273003F000000";
  auto name = networkShareItem(data);
  ASSERT_TRUE(name == "\\\\vmware-host\\Shared Folders");
}

} // namespace osquery