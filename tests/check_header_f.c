#include "../config.h"

#include <stdlib.h>

#ifdef HAVE_CHECK_H

#include <check.h>
#include "../src/header_f.h"

#define RUNNING_CHECK 1

int verbose = 99;

char *transport_str = "UDP";

void exit_code(int code, const char *function, const char *reason) {
  ck_abort_msg("Unexpected call to exit_code() with code %i at %s: %s",
      code, function, reason);
};

char const* chk_null_str(char const* str) {
	return str ? str : "<NULL>";
}

START_TEST (test_get_cl) {
	/* failure cases */
	ck_assert_msg(get_cl("") == -1, "get_cl(\"\") returned %d, instead of -1", get_cl(""));
	ck_assert_msg(get_cl("a") == -1, "get_cl(\"a\") returned %d, instead of -1", get_cl("a"));

	/* success cases */
	ck_assert_msg(get_cl("Content-Length: 123") == 123, "get_cl(\"123\") returned %d, instead of 123", get_cl("Content_Length: 123"));
	ck_assert_msg(get_cl("Content-Length: 321\r\n") == 321, "get_cl(\"321\") returned %d, instead of 321", get_cl("Content_Length: 321\r\n"));
	ck_assert_msg(get_cl("\nl: 456") == 456, "get_cl(\"456\") returned %d, instead of 456", get_cl("\nl: 456"));
	ck_assert_msg(get_cl("\nl: 789\r\n") == 789, "get_cl(\"789\") returned %d, instead of 789", get_cl("\nl: 789\r\n"));
}
END_TEST

START_TEST (test_find_lr_parameter) {
	/* failure cases */
	ck_assert_msg(find_lr_parameter("") == 0, "find_lr_parameter(\"\") returned %d, instead of 0", find_lr_parameter(""));
	ck_assert_msg(find_lr_parameter("a") == 0, "find_lr_parameter(\"a\") returned %d, instead of 0", find_lr_parameter("a"));
	ck_assert_msg(find_lr_parameter(";lr") == 0, "find_lr_parameter(\";lr\") returned %d, instead of 0", find_lr_parameter(";lr"));
	ck_assert_msg(find_lr_parameter("\n") == 0, "find_lr_parameter(\"\\n\") returned %d, instead of 0", find_lr_parameter("\n"));
	ck_assert_msg(find_lr_parameter("aaa\nbbb") == 0, "find_lr_parameter(\"aaa\\nbbb\") returned %d, instead of 0", find_lr_parameter("aaa\nbbb"));
	ck_assert_msg(find_lr_parameter("a\n;lr") == 0, "find_lr_parameter(\"a\n;lr\") returned %d, instead of 0", find_lr_parameter("a\n;lr"));

	/* success cases */
	ck_assert_msg(find_lr_parameter(";lr\n") == 1, "find_lr_parameter(\";lr\n\") returned %d, instead of 1", find_lr_parameter(";lr\n"));
	ck_assert_msg(find_lr_parameter("Record-Route: foo;lr\n") == 1, "find_lr_parameter(\"Record-Route: foo;lr\n\") returned %d, instead of 1", find_lr_parameter(";lr\n"));
}
END_TEST

START_TEST(test_parse_uri) {
	char uri[100], *cur_uri;
	char *scheme, *user, *host;
	int port = 0;

	char *msg_str = "parse_uri(\"%s\") returned \"%s\", \"%s\", \"%s\", \"%d\"";

	cur_uri = "sip:username@127.0.0.1:5060";
	strcpy(uri, cur_uri);
	parse_uri(uri, &scheme, &user, &host, &port);
	ck_assert_msg(strcmp(chk_null_str(scheme), "sip") == 0 && strcmp(chk_null_str(user), "username") == 0 && strcmp(chk_null_str(host), "127.0.0.1") == 0 && port == 5060, msg_str, cur_uri, chk_null_str(scheme), chk_null_str(user), chk_null_str(host), port);

	cur_uri = "sip:username@[::0]:5060";
	strcpy(uri, cur_uri);
	parse_uri(uri, &scheme, &user, &host, &port);
	ck_assert_msg(strcmp(chk_null_str(scheme), "sip") == 0 && strcmp(chk_null_str(user), "username") == 0 && strcmp(chk_null_str(host), "::0") == 0 && port == 5060, msg_str, cur_uri, chk_null_str(scheme), chk_null_str(user), chk_null_str(host), port);

	cur_uri = "username@[::0]:5060";
	strcpy(uri, cur_uri);
	parse_uri(uri, &scheme, &user, &host, &port);
	ck_assert_msg(scheme == NULL && strcmp(chk_null_str(user), "username") == 0 && strcmp(chk_null_str(host), "::0") == 0 && port == 5060, msg_str, cur_uri, chk_null_str(scheme), chk_null_str(user), chk_null_str(host), port);

	cur_uri = "username@[::0]";
	strcpy(uri, cur_uri);
	parse_uri(uri, &scheme, &user, &host, &port);
	ck_assert_msg(scheme == NULL && strcmp(chk_null_str(user), "username") == 0 && strcmp(chk_null_str(host), "::0") == 0 && port == 0, msg_str, cur_uri, chk_null_str(scheme), chk_null_str(user), chk_null_str(host), port);

	cur_uri = "username@[::0]:5060";
	strcpy(uri, cur_uri);
	parse_uri(uri, &scheme, &user, &host, &port);
	ck_assert_msg(scheme == NULL && strcmp(chk_null_str(user), "username") == 0 && strcmp(chk_null_str(host), "::0") == 0 && port == 5060, msg_str, cur_uri, chk_null_str(scheme), chk_null_str(user), chk_null_str(host), port);

	cur_uri = "[::0]:5060";
	strcpy(uri, cur_uri);
	parse_uri(uri, &scheme, &user, &host, &port);
	ck_assert_msg(scheme == NULL && user == NULL && strcmp(chk_null_str(host), "::0") == 0 && port == 5060, msg_str, cur_uri, chk_null_str(scheme), chk_null_str(user), chk_null_str(host), port);

	cur_uri = "127.0.0.1:5060";
	strcpy(uri, cur_uri);
	parse_uri(uri, &scheme, &user, &host, &port);
	ck_assert_msg(scheme == NULL && user == NULL && strcmp(chk_null_str(host), "127.0.0.1") == 0 && port == 5060, msg_str, cur_uri, chk_null_str(scheme), chk_null_str(user), chk_null_str(host), port);

	cur_uri = "sip:[::0]:5080";
	strcpy(uri, cur_uri);
	parse_uri(uri, &scheme, &user, &host, &port);
	ck_assert_msg(strcmp(chk_null_str(scheme), "sip") == 0 && user == NULL && strcmp(chk_null_str(host), "::0") == 0 && port == 5080, msg_str, cur_uri, chk_null_str(scheme), chk_null_str(user), chk_null_str(host), port);

	cur_uri = "sip:127.0.0.1:5060";
	strcpy(uri, cur_uri);
	parse_uri(uri, &scheme, &user, &host, &port);
	ck_assert_msg(strcmp(chk_null_str(scheme), "sip") == 0 && user == NULL && strcmp(chk_null_str(host), "127.0.0.1") == 0 && port == 5060, msg_str, cur_uri, chk_null_str(scheme), chk_null_str(user), chk_null_str(host), port);
}
END_TEST

START_TEST (test_get_cseq) {
	/* failure cases */
	ck_assert_msg(get_cseq("") == 0, "get_cseq(\"\") returned %d, instead of 0", find_lr_parameter(""));
	ck_assert_msg(get_cseq("foo") == 0, "get_cseq(\"foo\") returned %d, instead of 0", find_lr_parameter("foo"));
	ck_assert_msg(get_cseq("Cseq: ") == 0, "get_cseq(\"Cseq: \") returned %d, instead of 0", find_lr_parameter("Cseq: "));
	ck_assert_msg(get_cseq("Cseq: -5") == 0, "get_cseq(\"Cseq: -5\") returned %d, instead of 0", find_lr_parameter("Cseq: -5"));
	ck_assert_msg(get_cseq("Cseq: a") == 0, "get_cseq(\"Cseq: a\") returned %d, instead of 0", find_lr_parameter("Cseq: a"));

	/* success cases */
	ck_assert_msg(get_cseq("Cseq: 1") == 1, "get_cseq(\"Cseq: 1\") returned %d, instead of 1", find_lr_parameter("Cseq: 1"));
	ck_assert_msg(get_cseq("Cseq: 123456") == 123456, "get_cseq(\"Cseq: 123456\") returned %d, instead of 123456", find_lr_parameter("Cseq: 123456"));
}
END_TEST

Suite *header_f_suite(void) {
	Suite *s = suite_create("Header_f");

	/* get_cl test case */
	TCase *tc_get_cl = tcase_create("get_cl");
	tcase_add_test(tc_get_cl, test_get_cl);
	/* find_lr_parameter test case */
	TCase *tc_find_lr_parameter = tcase_create("find_lr_parameter");
	tcase_add_test(tc_find_lr_parameter, test_find_lr_parameter);
	/* parse_uri test case */
	TCase *tc_parse_uri = tcase_create("parse_uri");
	tcase_add_test(tc_parse_uri, test_parse_uri);
	/* get_cseq test case */
	TCase *tc_get_cseq = tcase_create("get_cseq");
	tcase_add_test(tc_get_cseq, test_get_cseq);

	/* add test cases to suite */
	suite_add_tcase(s, tc_get_cl);
	suite_add_tcase(s, tc_find_lr_parameter);
	suite_add_tcase(s, tc_parse_uri);
	suite_add_tcase(s, tc_get_cseq);

	return s;
}

int main(void) {
	int number_failed;
	Suite *s = header_f_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_VERBOSE);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

#else /* HAVE_CHECK_H */

#include <stdio.h>
int main(void) {
	printf("check_helper: !!! missing check unit test framework !!!\n");
	return EXIT_FAILURE;
}

#endif /* HAVE_CHECK_H */
