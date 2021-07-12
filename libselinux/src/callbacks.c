/*
 * User-supplied callbacks and default implementations.
 * Class and permission mappings.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <selinux/selinux.h>
#include "callbacks.h"

/*
	comment by Clark::   
最近，在看libevent源码，第一次看到__attribute__((format(printf, a, b)))这种写法。因此，在这里记录下用法。
　　功能：__attribute__ format 属性可以给被声明的函数加上类似printf或者scanf的特征, 它可以使编译器检查函数声明和函数实际调用参数之间的格式化字符串是否匹配。
	format属性告诉编译器，按照printf, scanf等标准C函数参数格式规则对该函数的参数进行检查。这在我们自己封装调试信息的接口时非常的有用。

　　format的语法格式为：
	format (archetype, string-index, first-to-check)
　　其中，"archetype" 指定是哪种风格: "string-index" 指定传入函数的第几个参数是格式化字符串: 
	"first-to-check" 指定从函数的第几个参数开始按上述规则进行检查.

具体的使用如下所示：
__attribute__((format(printf, a, b)))
__attribute__((format(scanf, a, b)))
　　其中参数m与n的含义为：
　　　　a：第几个参数为格式化字符串(format string);
　　　　b：参数集合中的第一个，即参数“…”里的第一个参数在函数参数总数排在第几。

	::2021-4-9
*/ 

/* default implementations */
static int __attribute__ ((format(printf, 2, 3)))
default_selinux_log(int type __attribute__((unused)), const char *fmt, ...)
{
	int rc;
	va_list ap;
	va_start(ap, fmt);
	rc = vfprintf(stderr, fmt, ap);
	va_end(ap);
	return rc;
}

static int
default_selinux_audit(void *ptr __attribute__((unused)),
		      security_class_t cls __attribute__((unused)),
		      char *buf __attribute__((unused)),
		      size_t len __attribute__((unused)))
{
	return 0;
}

static int
default_selinux_validate(char **ctx)
{
	return security_check_context(*ctx);
}

static int
default_selinux_setenforce(int enforcing __attribute__((unused)))
{
	return 0;
}

static int
default_selinux_policyload(int seqno __attribute__((unused)))
{
	return 0;
}

/* callback pointers */
int __attribute__ ((format(printf, 2, 3)))
(*selinux_log)(int, const char *, ...) =
	default_selinux_log;

int
(*selinux_audit) (void *, security_class_t, char *, size_t) =
	default_selinux_audit;

int
(*selinux_validate)(char **ctx) =
	default_selinux_validate;

int
(*selinux_netlink_setenforce) (int enforcing) =
	default_selinux_setenforce;

int
(*selinux_netlink_policyload) (int seqno) =
	default_selinux_policyload;

/* callback setting function */
void
selinux_set_callback(int type, union selinux_callback cb)
{
	switch (type) {
	case SELINUX_CB_LOG:
		selinux_log = cb.func_log;
		break;
	case SELINUX_CB_AUDIT:
		selinux_audit = cb.func_audit;
		break;
	case SELINUX_CB_VALIDATE:
		selinux_validate = cb.func_validate;
		break;
	case SELINUX_CB_SETENFORCE:
		selinux_netlink_setenforce = cb.func_setenforce;
		break;
	case SELINUX_CB_POLICYLOAD:
		selinux_netlink_policyload = cb.func_policyload;
		break;
	}
}

/* callback getting function */
union selinux_callback
selinux_get_callback(int type)
{
	union selinux_callback cb;

	switch (type) {
	case SELINUX_CB_LOG:
		cb.func_log = selinux_log;
		break;
	case SELINUX_CB_AUDIT:
		cb.func_audit = selinux_audit;
		break;
	case SELINUX_CB_VALIDATE:
		cb.func_validate = selinux_validate;
		break;
	case SELINUX_CB_SETENFORCE:
		cb.func_setenforce = selinux_netlink_setenforce;
		break;
	case SELINUX_CB_POLICYLOAD:
		cb.func_policyload = selinux_netlink_policyload;
		break;
	default:
		memset(&cb, 0, sizeof(cb));
		errno = EINVAL;
		break;
	}
	return cb;
}
