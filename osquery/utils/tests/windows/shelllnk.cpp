/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>
#include <osquery/utils/windows/shelllnk.h>

#include <string>

namespace osquery {
class ShelllnkTests : pubilc testing::Test {};

TEST_F(ShelllnkTests, test_shelllnk_header) {
  std::string data =
      "4C0000000114020000000000C0000000000000469B00200020000000B08E934EEF12D701"
      "B08E934EEF12D701B08E934EEF12D7010000000000000000010000000000000000000000"
      "00000000110314001F50E04FD020EA3A6910A2D808002B30309D19002F433A5C00000000"
      "0000000000000000000000000000007800310000000000554FC0BC110055736572730064"
      "0009000400EFBE734EAC24554FC0BC2E0000001E9201000000060000000000000000003A"
      "00000000003B3FF40055007300650072007300000040007300680065006C006C00330032"
      "002E0064006C006C002C002D0032003100380031003300000014004A003100000000004D"
      "5257341000626F6200380009000400EFBE554F3D104D5257342E00000087260300000005"
      "00000000000000000000000000000097AA840062006F006200000012007E003100000000"
      "006552392911004465736B746F7000680009000400EFBE554FAD09655239292E00000065"
      "2603000000070000000000000000003E00000000006B716A004400650073006B0074006F"
      "007000000040007300680065006C006C00330032002E0064006C006C002C002D00320031"
      "00370036003900000016004E003100000000006752D30910006E61766900003A00090004"
      "00EFBE6752D3096752D3092E0000006FAF00000000990000000000000000000000000000"
      "00CA220B006E00610076006900000014004A003100000000006752D70910006865790038"
      "0009000400EFBE6752D7096752D7092E00000071AF000000007E00000000000000000000"
      "000000000043EE84006800650079000000120054003100000000006752DA0910006C6973"
      "74656E00003E0009000400EFBE6752DA096752DA092E00000074AF000000007000000000"
      "000000000000000000000022D14D006C0069007300740065006E00000016004A00310000"
      "0000006752E00910006C6E6B00380009000400EFBE6752E0096752E0092E00000076AF00"
      "0000006D000000000000000000000000000000A249F0006C006E006B00000012006C0032"
      "00000000006752E3092000534156455F487E312E5458540000500009000400EFBE6752E3"
      "096752E3092E0000007DAF000000007200000000000000000000000000000050BA440073"
      "006100760065005F0068007900720075006C0065002E0074007800740000001C00000067"
      "0000001C000000010000001C0000002D000000000000006600000011000000030000006F"
      "129DD41000000000433A5C55736572735C626F625C4465736B746F705C6E6176695C6865"
      "795C6C697374656E5C6C6E6B5C736176655F687972756C652E74787400003A002E002E00"
      "5C002E002E005C002E002E005C002E002E005C002E002E005C004400650073006B007400"
      "6F0070005C006E006100760069005C006800650079005C006C0069007300740065006E00"
      "5C006C006E006B005C0073006100760065005F0068007900720075006C0065002E007400"
      "78007400280043003A005C00550073006500720073005C0062006F0062005C0044006500"
      "73006B0074006F0070005C006E006100760069005C006800650079005C006C0069007300"
      "740065006E005C006C006E006B0060000000030000A058000000000000006465736B746F"
      "702D6569733933386E0068458D3E11E418498F7897CD6CB340C5AC94C210D67EEB11A0F6"
      "0800276EB45E68458D3E11E418498F7897CD6CB340C5AC94C210D67EEB11A0F60800276E"
      "B45E45000000090000A03900000031535053B1166D44AD8D7048A748402EA43D788C1D00"
      "0000680000000048000000902F5408000000000000501F00000000000000000000000000"
      "000000";
  auto header_data = parseShortcutHeader(data);
  ASSERT_TRUE(header_data.modified == 1615079705);
  ASSERT_TRUE(header_data.created == 1615079705);
  ASSERT_TRUE(header_data.accessed == 1615079705);
  ASSERT_TRUE(header_data.file_size == 0);
}

TEST_F(ShelllnkTests, test_shelllnk_target_info) {
  std::string data =
      "110314001F50E04FD020EA3A6910A2D808002B30309D19002F433A5C0000000000000000"
      "00000000000000000000007800310000000000554FC0BC11005573657273006400090004"
      "00EFBE734EAC24554FC0BC2E0000001E9201000000060000000000000000003A00000000"
      "003B3FF40055007300650072007300000040007300680065006C006C00330032002E0064"
      "006C006C002C002D0032003100380031003300000014004A003100000000004D52573410"
      "00626F6200380009000400EFBE554F3D104D5257342E0000008726030000000500000000"
      "000000000000000000000097AA840062006F006200000012007E00310000000000655239"
      "2911004465736B746F7000680009000400EFBE554FAD09655239292E0000006526030000"
      "00070000000000000000003E00000000006B716A004400650073006B0074006F00700000"
      "0040007300680065006C006C00330032002E0064006C006C002C002D0032003100370036"
      "003900000016004E003100000000006752D30910006E61766900003A0009000400EFBE67"
      "52D3096752D3092E0000006FAF0000000099000000000000000000000000000000CA220B"
      "006E00610076006900000014004A003100000000006752D7091000686579003800090004"
      "00EFBE6752D7096752D7092E00000071AF000000007E0000000000000000000000000000"
      "0043EE84006800650079000000120054003100000000006752DA0910006C697374656E00"
      "003E0009000400EFBE6752DA096752DA092E00000074AF00000000700000000000000000"
      "0000000000000022D14D006C0069007300740065006E00000016004A0031000000000067"
      "52E00910006C6E6B00380009000400EFBE6752E0096752E0092E00000076AF000000006D"
      "000000000000000000000000000000A249F0006C006E006B00000012006C003200000000"
      "006752E3092000534156455F487E312E5458540000500009000400EFBE6752E3096752E3"
      "092E0000007DAF000000007200000000000000000000000000000050BA44007300610076"
      "0065005F0068007900720075006C0065002E0074007800740000001C000000670000001C"
      "000000010000001C0000002D000000000000006600000011000000030000006F129DD410"
      "00000000433A5C55736572735C626F625C4465736B746F705C6E6176695C6865795C6C69"
      "7374656E5C6C6E6B5C736176655F687972756C652E74787400003A002E002E005C002E00"
      "2E005C002E002E005C002E002E005C002E002E005C004400650073006B0074006F007000"
      "5C006E006100760069005C006800650079005C006C0069007300740065006E005C006C00"
      "6E006B005C0073006100760065005F0068007900720075006C0065002E00740078007400"
      "280043003A005C00550073006500720073005C0062006F0062005C004400650073006B00"
      "74006F0070005C006E006100760069005C006800650079005C006C006900730074006500"
      "6E005C006C006E006B0060000000030000A058000000000000006465736B746F702D6569"
      "733933386E0068458D3E11E418498F7897CD6CB340C5AC94C210D67EEB11A0F60800276E"
      "B45E68458D3E11E418498F7897CD6CB340C5AC94C210D67EEB11A0F60800276EB45E4500"
      "0000090000A03900000031535053B1166D44AD8D7048A748402EA43D788C1D0000006800"
      "00000048000000902F5408000000000000501F00000000000000000000000000000000";

  auto target_info = parseTargetInfo(data);
  ASSERT_TRUE(
      target_info.path,
      "This PC\\C:\\Users\\bob\\Desktop\\navi\\hey\\listen\\lnk\\save_hyrule.txt");
  ASSERT_TRUE(target_info.mft_entry == 44925);
  ASSERT_TRUE(target_info.mft_sequence == 114);
}

TEST_F(ShelllnkTests, test_shelllnk_location_info) {
  std::string data =
      "0000670000001C000000010000001C0000002D0000000000000066000000110000000300"
      "00006F129DD41000000000433A5C55736572735C626F625C4465736B746F705C6E617669"
      "5C6865795C6C697374656E5C6C6E6B5C736176655F687972756C652E74787400003A002E"
      "002E005C002E002E005C002E002E005C002E002E005C002E002E005C004400650073006B"
      "0074006F0070005C006E006100760069005C006800650079005C006C0069007300740065"
      "006E005C006C006E006B005C0073006100760065005F0068007900720075006C0065002E"
      "00740078007400280043003A005C00550073006500720073005C0062006F0062005C0044"
      "00650073006B0074006F0070005C006E006100760069005C006800650079005C006C0069"
      "007300740065006E005C006C006E006B0060000000030000A05800000000000000646573"
      "6B746F702D6569733933386E0068458D3E11E418498F7897CD6CB340C5AC94C210D67EEB"
      "11A0F60800276EB45E68458D3E11E418498F7897CD6CB340C5AC94C210D67EEB11A0F608"
      "00276EB45E45000000090000A03900000031535053B1166D44AD8D7048A748402EA43D78"
      "8C1D000000680000000048000000902F5408000000000000501F00000000000000000000"
      "000000000000";
  auto location_info = parseLocationData(data);
  ASSERT_TRUE(location_info.local_path,
              "C:\\Users\\bob\\Desktop\\navi\\hey\\listen\\lnk\\save_hyrule.txt");
  ASSERT_TRUE(location_info.type, "Fixed storage media (harddisk)");
  ASSERT_TRUE(location_info.serial, "D49D126F");
}

TEST_F(ShelllnkTests, test_shelllnk_data_string) {
  std::string data =
      "3A002E002E005C002E002E005C002E002E005C002E002E005C002E002E005C0044006500"
      "73006B0074006F0070005C006E006100760069005C006800650079005C006C0069007300"
      "740065006E005C006C006E006B005C0073006100760065005F0068007900720075006C00"
      "65002E00740078007400280043003A005C00550073006500720073005C0062006F006200"
      "5C004400650073006B0074006F0070005C006E006100760069005C006800650079005C00"
      "6C0069007300740065006E005C006C006E006B0060000000030000A05800000000000000"
      "6465736B746F702D6569733933386E0068458D3E11E418498F7897CD6CB340C5AC94C210"
      "D67EEB11A0F60800276EB45E68458D3E11E418498F7897CD6CB340C5AC94C210D67EEB11"
      "A0F60800276EB45E45000000090000A03900000031535053B1166D44AD8D7048A748402E"
      "A43D788C1D000000680000000048000000902F5408000000000000501F00000000000000"
      "000000000000000000";
  auto data_string = parseDataString(data, true, false, true, true, false, false);
  ASSERT_TRUE(data_string.relative_path, "..\\..\\..\\..\\..\\Desktop\\navi\\hey\\listen\\lnk\\save_hyrule.txt");
}

TEST_F(ShelllnkTests, test_shelllnk_extra_data_tracker) {
  std::string data =
      "60000000030000A058000000000000006465736B746F702D6569733933386E0068458D3E"
      "11E418498F7897CD6CB340C5AC94C210D67EEB11A0F60800276EB45E68458D3E11E41849"
      "8F7897CD6CB340C5AC94C210D67EEB11A0F60800276EB45E45000000090000A039000000"
      "31535053B1166D44AD8D7048A748402EA43D788C1D000000680000000048000000902F54"
      "08000000000000501F00000000000000000000000000000000";
  auto extra_data = parseExtraDataTracker(data);
  ASSERT_TRUE(extra_data.hostname, "desktop-eis938n");
}
}