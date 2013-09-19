/*
  +----------------------------------------------------------------------+
  | APC                                                                  |
  +----------------------------------------------------------------------+
  | Copyright (c) 2006-2011 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt.                                 |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Authors: Daniel Cowgill <dcowgill@communityconnect.com>              |
  |          Rasmus Lerdorf <rasmus@php.net>                             |
  |          Arun C. Murthy <arunc@yahoo-inc.com>                        |
  |          Gopal Vijayaraghavan <gopalv@yahoo-inc.com>                 |
  +----------------------------------------------------------------------+

   This software was contributed to PHP by Community Connect Inc. in 2002
   and revised in 2005 by Yahoo! Inc. to add support for PHP 5.1.
   Future revisions and derivatives of this source code must acknowledge
   Community Connect Inc. as the original contributor of this module by
   leaving this note intact in the source code.

   All other licensing and usage conditions are those of the PHP Group.

 */

/* $Id: apc_compile.c 327148 2012-08-16 14:11:18Z laruence $ */

#include "apc_compile.h"
#include "apc_globals.h"
#include "apc_zend.h"
#include "apc_php.h"
#include "apc_string.h"
#include "ext/standard/php_var.h"
#include "ext/standard/php_smart_str.h"

typedef void* (*ht_copy_fun_t)(void*, void*, apc_context_t* TSRMLS_DC);
//typedef void  (*ht_free_fun_t)(void*, apc_context_t*);
typedef int (*ht_check_copy_fun_t)(Bucket*, va_list);

typedef void (*ht_fixup_fun_t)(Bucket*, zend_class_entry*, zend_class_entry*);

#define CHECK(p) { if ((p) == NULL) return NULL; }

enum {
    APC_FREE_HASHTABLE_FUNCS,
    APC_FREE_HASHTABLE_PROPS,
    APC_FREE_HASHTABLE_STATIC_PROPS,
};

/* {{{ internal function declarations */

static zend_function* my_bitwise_copy_function(zend_function*, zend_function*, apc_context_t* TSRMLS_DC);

/*
 * The "copy" functions perform deep-copies on a particular data structure
 * (passed as the second argument). They also optionally allocate space for
 * the destination data structure if the first argument is null.
 */
static zval** my_copy_zval_ptr(zval**, const zval**, apc_context_t* TSRMLS_DC);
static zval* my_copy_zval(zval*, const zval*, apc_context_t* TSRMLS_DC);
#ifndef ZEND_ENGINE_2_4
static znode* my_copy_znode(znode*, znode*, apc_context_t* TSRMLS_DC);
#endif
static zend_op* my_copy_zend_op(zend_op*, zend_op*, apc_context_t* TSRMLS_DC);
static zend_function* my_copy_function(zend_function*, zend_function*, apc_context_t* TSRMLS_DC);
static zend_function_entry* my_copy_function_entry(zend_function_entry*, const zend_function_entry*, apc_context_t* TSRMLS_DC);
static zend_class_entry* my_copy_class_entry(zend_class_entry*, zend_class_entry*, apc_context_t* TSRMLS_DC);
static HashTable* my_copy_hashtable_ex(HashTable*, HashTable* TSRMLS_DC, ht_copy_fun_t, int, apc_context_t*, ht_check_copy_fun_t, ...);
#define my_copy_hashtable( dst, src, copy_fn, holds_ptr, ctxt) \
    my_copy_hashtable_ex(dst, src TSRMLS_CC, copy_fn, holds_ptr, ctxt, NULL)
static HashTable* my_copy_static_variables(zend_op_array* src, apc_context_t* TSRMLS_DC);
static zend_property_info* my_copy_property_info(zend_property_info* dst, zend_property_info* src, apc_context_t* TSRMLS_DC);
static zend_arg_info* my_copy_arg_info_array(zend_arg_info*, const zend_arg_info*, uint, apc_context_t* TSRMLS_DC);
static zend_arg_info* my_copy_arg_info(zend_arg_info*, const zend_arg_info*, apc_context_t* TSRMLS_DC);

/*
 * The "fixup" functions need for ZEND_ENGINE_2
 */
static void my_fixup_function( Bucket *p, zend_class_entry *src, zend_class_entry *dst );
static void my_fixup_hashtable( HashTable *ht, ht_fixup_fun_t fixup, zend_class_entry *src, zend_class_entry *dst );
/* my_fixup_function_for_execution is the same as my_fixup_function
 * but named differently for clarity
 */
#define my_fixup_function_for_execution my_fixup_function

#ifdef ZEND_ENGINE_2_2
static void my_fixup_property_info( Bucket *p, zend_class_entry *src, zend_class_entry *dst );
#define my_fixup_property_info_for_execution my_fixup_property_info
#endif

/*
 * These functions return "1" if the member/function is
 * defined/overridden in the 'current' class and not inherited.
 */
static int my_check_copy_function(Bucket* src, va_list args);
static int my_check_copy_property_info(Bucket* src, va_list args);
#ifndef ZEND_ENGINE_2_4
static int my_check_copy_default_property(Bucket* p, va_list args);
static int my_check_copy_static_member(Bucket* src, va_list args);
#endif
static int my_check_copy_constant(Bucket* src, va_list args);

/* }}} */

/* {{{ apc php serializers */
int APC_SERIALIZER_NAME(php) (APC_SERIALIZER_ARGS) 
{
    smart_str strbuf = {0};
    php_serialize_data_t var_hash;
    PHP_VAR_SERIALIZE_INIT(var_hash);
    php_var_serialize(&strbuf, (zval**)&value, &var_hash TSRMLS_CC);
    PHP_VAR_SERIALIZE_DESTROY(var_hash);
    if(strbuf.c) {
        *buf = (unsigned char*)strbuf.c;
        *buf_len = strbuf.len;
        smart_str_0(&strbuf);
        return 1; 
    }
    return 0;
}

int APC_UNSERIALIZER_NAME(php) (APC_UNSERIALIZER_ARGS) 
{
    const unsigned char *tmp = buf;
    php_unserialize_data_t var_hash;
    PHP_VAR_UNSERIALIZE_INIT(var_hash);
    if(!php_var_unserialize(value, &tmp, buf + buf_len, &var_hash TSRMLS_CC)) {
        PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
        zval_dtor(*value);
        php_error_docref(NULL TSRMLS_CC, E_NOTICE, "Error at offset %ld of %ld bytes", (long)(tmp - buf), (long)buf_len);
        (*value)->type = IS_NULL;
        return 0;
    }
    PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
    return 1;
}
/* }}} */

/* {{{ check_op_array_integrity */
#if 0
static void check_op_array_integrity(zend_op_array* src)
{
    int i, j;

    /* These sorts of checks really aren't particularly effective, but they
     * can provide a welcome sanity check when debugging. Just don't enable
     * for production use!  */

    assert(src->refcount != NULL);
    assert(src->opcodes != NULL);
    assert(src->last > 0);

    for (i = 0; i < src->last; i++) {
        zend_op* op = &src->opcodes[i];
        znode* nodes[] = { &op->result, &op->op1, &op->op2 };
        for (j = 0; j < 3; j++) {
            assert(nodes[j]->op_type == IS_CONST ||
                   nodes[j]->op_type == IS_VAR ||
                   nodes[j]->op_type == IS_TMP_VAR ||
                   nodes[j]->op_type == IS_UNUSED);

            if (nodes[j]->op_type == IS_CONST) {
                int type = nodes[j]->u.constant.type;
                assert(type == IS_RESOURCE ||
                       type == IS_BOOL ||
                       type == IS_LONG ||
                       type == IS_DOUBLE ||
                       type == IS_NULL ||
                       type == IS_CONSTANT ||
                       type == IS_STRING ||
                       type == FLAG_IS_BC ||
                       type == IS_ARRAY ||
                       type == IS_CONSTANT_ARRAY ||
                       type == IS_OBJECT);
            }
        }
    }
}
#endif
/* }}} */

/* {{{ my_bitwise_copy_function */
static zend_function* my_bitwise_copy_function(zend_function* dst, zend_function* src, apc_context_t* ctxt TSRMLS_DC)
{
    apc_pool* pool = ctxt->pool;

    assert(src != NULL);

    if (!dst) {
        CHECK(dst = (zend_function*) apc_pool_alloc(pool, sizeof(src[0])));
    }

    /* We only need to do a bitwise copy */
    memcpy(dst, src, sizeof(src[0]));

    return dst;
}
/* }}} */

/* {{{ my_copy_zval_ptr */
static zval** my_copy_zval_ptr(zval** dst, const zval** src, apc_context_t* ctxt TSRMLS_DC)
{
    zval* dst_new;
    apc_pool* pool = ctxt->pool;
    int usegc = (ctxt->copy == APC_COPY_OUT_OPCODE) || (ctxt->copy == APC_COPY_OUT_USER);

    assert(src != NULL);

    if (!dst) {
        CHECK(dst = (zval**) apc_pool_alloc(pool, sizeof(zval*)));
    }

    if(usegc) {
        ALLOC_ZVAL(dst[0]);
        CHECK(dst[0]);
    } else {
        CHECK((dst[0] = (zval*) apc_pool_alloc(pool, sizeof(zval))));
    }

    CHECK((dst_new = my_copy_zval(*dst, *src, ctxt TSRMLS_CC)));

    if(dst_new != *dst) {
        if(usegc) {
            FREE_ZVAL(dst[0]);
        }
        *dst = dst_new;
    }

    return dst;
}
/* }}} */

/* {{{ my_serialize_object */
static zval* my_serialize_object(zval* dst, const zval* src, apc_context_t* ctxt TSRMLS_DC)
{
    smart_str buf = {0};
    apc_pool* pool = ctxt->pool;
    apc_serialize_t serialize = APC_SERIALIZER_NAME(php);
    void *config = NULL;

    if(APCG(serializer)) { /* TODO: move to ctxt */
        serialize = APCG(serializer)->serialize;
        config = APCG(serializer)->config;
    }

    if(serialize((unsigned char**)&buf.c, &buf.len, src, config TSRMLS_CC)) {
        dst->type = src->type & ~IS_CONSTANT_INDEX; 
        dst->value.str.len = buf.len;
        CHECK(dst->value.str.val = apc_pmemcpy(buf.c, (buf.len + 1), pool TSRMLS_CC));
    }

    if(buf.c) smart_str_free(&buf);

    return dst;
}
/* }}} */

/* {{{ my_unserialize_object */
static zval* my_unserialize_object(zval* dst, const zval* src, apc_context_t* ctxt TSRMLS_DC)
{
    apc_unserialize_t unserialize = APC_UNSERIALIZER_NAME(php);
    unsigned char *p = (unsigned char*)Z_STRVAL_P(src);
    void *config = NULL;

    if(APCG(serializer)) { /* TODO: move to ctxt */
        unserialize = APCG(serializer)->unserialize;
        config = APCG(serializer)->config;
    }

    if(unserialize(&dst, p, Z_STRLEN_P(src), config TSRMLS_CC)) {
        return dst;
    } else {
        zval_dtor(dst);
        dst->type = IS_NULL;
    }
    return dst;
}
/* }}} */

/* {{{ apc_string_pmemcpy */
static char *apc_string_pmemcpy(char *str, size_t len, apc_pool* pool TSRMLS_DC)
{	
#ifdef ZEND_ENGINE_2_4
#ifndef ZTS
    if (pool->type != APC_UNPOOL) {
        char * ret = (char*)apc_new_interned_string((const char*)str, len TSRMLS_CC);
        if (ret) {
            return ret;
        }
    }
#endif
#endif
    return apc_pmemcpy(str, len, pool TSRMLS_CC);
}
/* }}} */

/* {{{ my_copy_zval */
static APC_HOTSPOT zval* my_copy_zval(zval* dst, const zval* src, apc_context_t* ctxt TSRMLS_DC)
{
    zval **tmp;
    apc_pool* pool = ctxt->pool;

    assert(dst != NULL);
    assert(src != NULL);

    memcpy(dst, src, sizeof(src[0]));

    if(APCG(copied_zvals).nTableSize) {
        if(zend_hash_index_find(&APCG(copied_zvals), (ulong)src, (void**)&tmp) == SUCCESS) {
            if(Z_ISREF_P((zval*)src)) {
                Z_SET_ISREF_PP(tmp);
            }
            Z_ADDREF_PP(tmp);
            return *tmp;
        }

        zend_hash_index_update(&APCG(copied_zvals), (ulong)src, (void**)&dst, sizeof(zval*), NULL);
    }


    if(ctxt->copy == APC_COPY_OUT_USER || ctxt->copy == APC_COPY_IN_USER) {
        /* deep copies are refcount(1), but moved up for recursive 
         * arrays,  which end up being add_ref'd during its copy. */
        Z_SET_REFCOUNT_P(dst, 1);
        Z_UNSET_ISREF_P(dst);
    } else {
        /* code uses refcount=2 for consts */
        Z_SET_REFCOUNT_P(dst, Z_REFCOUNT_P((zval*)src));
        Z_SET_ISREF_TO_P(dst, Z_ISREF_P((zval*)src));
    }

    switch (src->type & IS_CONSTANT_TYPE_MASK) {
    case IS_RESOURCE:
    case IS_BOOL:
    case IS_LONG:
    case IS_DOUBLE:
    case IS_NULL:
        break;

    case IS_CONSTANT:
    case IS_STRING:
        if (src->value.str.val) {
            CHECK(dst->value.str.val = apc_string_pmemcpy(src->value.str.val,
                                                   src->value.str.len+1,
                                                   pool TSRMLS_CC));
        }
        break;

    case IS_ARRAY:
    case IS_CONSTANT_ARRAY:
        if(APCG(serializer) == NULL ||
            ctxt->copy == APC_COPY_IN_OPCODE || ctxt->copy == APC_COPY_OUT_OPCODE) {

            CHECK(dst->value.ht =
                my_copy_hashtable(NULL,
                                  src->value.ht,
                                  (ht_copy_fun_t) my_copy_zval_ptr,
                                  1,
                                  ctxt));
            break;
        } else {
            /* fall through to object case */
        }

    case IS_OBJECT:
    
        dst->type = IS_NULL;
        if(ctxt->copy == APC_COPY_IN_USER) {
            dst = my_serialize_object(dst, src, ctxt TSRMLS_CC);
        } else if(ctxt->copy == APC_COPY_OUT_USER) {
            dst = my_unserialize_object(dst, src, ctxt TSRMLS_CC);
        }
        break;
#ifdef ZEND_ENGINE_2_4
    case IS_CALLABLE:
        /* XXX implement this */
        assert(0);
        break;
#endif

    default:
        assert(0);
    }

    return dst;
}
/* }}} */

#ifdef ZEND_ENGINE_2_4
/* {{{ my_copy_znode */
static void my_check_znode(zend_uchar op_type, apc_context_t* ctxt TSRMLS_DC)
{
    assert(op_type == IS_CONST ||
           op_type == IS_VAR ||
           op_type == IS_CV ||
           op_type == IS_TMP_VAR ||
           op_type == IS_UNUSED);
}
/* }}} */

/* {{{ my_copy_zend_op */
static zend_op* my_copy_zend_op(zend_op* dst, zend_op* src, apc_context_t* ctxt TSRMLS_DC)
{
    assert(dst != NULL);
    assert(src != NULL);

    memcpy(dst, src, sizeof(src[0]));

    my_check_znode(dst->result_type & ~EXT_TYPE_UNUSED, ctxt TSRMLS_CC);
    my_check_znode(dst->op1_type, ctxt TSRMLS_CC);

    /* ZEND_BIND_TRAITS opcode don't set the op2 at all, so ommit its check */
    if (dst->opcode != ZEND_BIND_TRAITS) {
        my_check_znode(dst->op2_type, ctxt TSRMLS_CC);
    }

    return dst;
}
/* }}} */
#else
/* {{{ my_copy_znode */
static znode* my_copy_znode(znode* dst, znode* src, apc_context_t* ctxt TSRMLS_DC)
{
    assert(dst != NULL);
    assert(src != NULL);

    memcpy(dst, src, sizeof(src[0]));

#ifdef IS_CV
    assert(dst ->op_type == IS_CONST ||
           dst ->op_type == IS_VAR ||
           dst ->op_type == IS_CV ||
           dst ->op_type == IS_TMP_VAR ||
           dst ->op_type == IS_UNUSED);
#else
    assert(dst ->op_type == IS_CONST ||
           dst ->op_type == IS_VAR ||
           dst ->op_type == IS_TMP_VAR ||
           dst ->op_type == IS_UNUSED);
#endif

    if (src->op_type == IS_CONST) {
        if(!my_copy_zval(&dst->u.constant, &src->u.constant, ctxt TSRMLS_CC)) {
            return NULL;
        }
    }

    return dst;
}
/* }}} */

/* {{{ my_copy_zend_op */
static zend_op* my_copy_zend_op(zend_op* dst, zend_op* src, apc_context_t* ctxt TSRMLS_DC)
{
    assert(dst != NULL);
    assert(src != NULL);

    memcpy(dst, src, sizeof(src[0]));

    CHECK(my_copy_znode(&dst->result, &src->result, ctxt TSRMLS_CC));
    CHECK(my_copy_znode(&dst->op1, &src->op1, ctxt TSRMLS_CC));
    CHECK(my_copy_znode(&dst->op2, &src->op2, ctxt TSRMLS_CC));

    return dst;
}
/* }}} */
#endif

/* {{{ my_copy_function */
static zend_function* my_copy_function(zend_function* dst, zend_function* src, apc_context_t* ctxt TSRMLS_DC)
{
    assert(src != NULL);

    CHECK(dst = my_bitwise_copy_function(dst, src, ctxt TSRMLS_CC));

    switch (src->type) {
    case ZEND_INTERNAL_FUNCTION:
    case ZEND_OVERLOADED_FUNCTION:
        /* shallow copy because op_array is internal */
        dst->op_array = src->op_array;
        break;

    case ZEND_USER_FUNCTION:
    case ZEND_EVAL_CODE:
        CHECK(apc_copy_op_array(&dst->op_array,
                                &src->op_array,
                                ctxt TSRMLS_CC));
        break;

    default:
        assert(0);
    }
    /*
     * op_array bitwise copying overwrites what ever you modified
     * before apc_copy_op_array - which is why this code is outside 
     * my_bitwise_copy_function.
     */

    /* zend_do_inheritance will re-look this up, because the pointers
     * in prototype are from a function table of another class. It just
     * helps if that one is from EG(class_table).
     */
    dst->common.prototype = NULL;

    /* once a method is marked as ZEND_ACC_IMPLEMENTED_ABSTRACT then you
     * have to carry around a prototype. Thankfully zend_do_inheritance
     * sets this properly as well
     */
    dst->common.fn_flags = src->common.fn_flags & (~ZEND_ACC_IMPLEMENTED_ABSTRACT);


    return dst;
}
/* }}} */

/* {{{ my_copy_function_entry */
static zend_function_entry* my_copy_function_entry(zend_function_entry* dst, const zend_function_entry* src, apc_context_t* ctxt TSRMLS_DC)
{
    assert(src != NULL);

    if (!dst) {
        CHECK(dst = (zend_function_entry*) apc_pool_alloc(ctxt->pool, sizeof(src[0])));
    }

    /* Start with a bitwise copy */
    memcpy(dst, src, sizeof(src[0]));

    dst->fname = NULL;
    dst->arg_info = NULL;

    if (src->fname) {
        CHECK((dst->fname = apc_pstrdup(src->fname, ctxt->pool TSRMLS_CC)));
    }

    if (src->arg_info) {
        CHECK((dst->arg_info = my_copy_arg_info_array(NULL,
                                                src->arg_info,
                                                src->num_args,
                                                ctxt TSRMLS_CC)));
    }

    return dst;
}
/* }}} */

/* {{{ my_copy_property_info */
static zend_property_info* my_copy_property_info(zend_property_info* dst, zend_property_info* src, apc_context_t* ctxt TSRMLS_DC)
{
    apc_pool* pool = ctxt->pool;

    assert(src != NULL);

    if (!dst) {
        CHECK(dst = (zend_property_info*) apc_pool_alloc(pool, sizeof(*src)));
    }

    /* Start with a bitwise copy */
    memcpy(dst, src, sizeof(*src));

    dst->name = NULL;
#if defined(ZEND_ENGINE_2) && PHP_MINOR_VERSION > 0
    dst->doc_comment = NULL;
#endif

    if (src->name) {
        /* private members are stored inside property_info as a mangled
         * string of the form:
         *      \0<classname>\0<membername>\0
         */
        CHECK((dst->name = apc_string_pmemcpy((char *)src->name, src->name_length+1, pool TSRMLS_CC)));
    }

#if defined(ZEND_ENGINE_2) && PHP_MINOR_VERSION > 0
    if (src->doc_comment) {
        CHECK((dst->doc_comment = apc_pmemcpy(src->doc_comment, (src->doc_comment_len + 1), pool TSRMLS_CC)));
    }
#endif

    return dst;
}
/* }}} */

/* {{{ my_copy_property_info_for_execution */
static zend_property_info* my_copy_property_info_for_execution(zend_property_info* dst, zend_property_info* src, apc_context_t* ctxt TSRMLS_DC)
{
    assert(src != NULL);

    if (!dst) {
        CHECK(dst = (zend_property_info*) apc_pool_alloc(ctxt->pool, sizeof(*src)));
    }

    /* We need only a shallow copy */
    memcpy(dst, src, sizeof(*src));

    return dst;
}
/* }}} */

/* {{{ my_copy_arg_info_array */
static zend_arg_info* my_copy_arg_info_array(zend_arg_info* dst, const zend_arg_info* src, uint num_args, apc_context_t* ctxt TSRMLS_DC)
{
    uint i = 0;


    if (!dst) {
        CHECK(dst = (zend_arg_info*) apc_pool_alloc(ctxt->pool, (sizeof(*src) * num_args)));
    }

    /* Start with a bitwise copy */
    memcpy(dst, src, sizeof(*src)*num_args);

    for(i=0; i < num_args; i++) {
        CHECK((my_copy_arg_info( &dst[i], &src[i], ctxt TSRMLS_CC)));
    }

    return dst;
}
/* }}} */

/* {{{ my_copy_arg_info */
static zend_arg_info* my_copy_arg_info(zend_arg_info* dst, const zend_arg_info* src, apc_context_t* ctxt TSRMLS_DC)
{
    apc_pool* pool = ctxt->pool;

    assert(src != NULL);

    if (!dst) {
        CHECK(dst = (zend_arg_info*) apc_pool_alloc(pool, sizeof(*src)));
    }

    /* Start with a bitwise copy */
    memcpy(dst, src, sizeof(*src));

    dst->name = NULL;
    dst->class_name = NULL;

    if (src->name) {
        CHECK((dst->name = apc_string_pmemcpy((char *) src->name, src->name_len+1, pool TSRMLS_CC)));
    }

    if (src->class_name) {
        CHECK((dst->class_name = apc_string_pmemcpy((char *) src->class_name, src->class_name_len+1, pool TSRMLS_CC)));
    }

    return dst;
}
/* }}} */

/* {{{ apc_copy_class_entry */
zend_class_entry* apc_copy_class_entry(zend_class_entry* dst, zend_class_entry* src, apc_context_t* ctxt TSRMLS_DC)
{
    return my_copy_class_entry(dst, src, ctxt TSRMLS_CC);
}
/* }}} */

/* {{{ my_copy_class_entry */
static zend_class_entry* my_copy_class_entry(zend_class_entry* dst, zend_class_entry* src, apc_context_t* ctxt TSRMLS_DC)
{
    int i = 0;
    apc_pool* pool = ctxt->pool;

    assert(src != NULL);

    if (!dst) {
        CHECK(dst = (zend_class_entry*) apc_pool_alloc(pool, sizeof(*src)));
    }

    /* Start with a bitwise copy */
    memcpy(dst, src, sizeof(*src));

    dst->name = NULL;
    memset(&dst->function_table, 0, sizeof(dst->function_table));
    ZEND_CE_DOC_COMMENT(dst) = NULL;
    ZEND_CE_FILENAME(dst) = NULL;
    memset(&dst->properties_info, 0, sizeof(dst->properties_info));
    memset(&dst->constants_table, 0, sizeof(dst->constants_table));

    if (src->name) {
        CHECK((dst->name = apc_pstrdup(src->name, pool TSRMLS_CC)));
    }

    if(!(my_copy_hashtable_ex(&dst->function_table,
                            &src->function_table TSRMLS_CC,
                            (ht_copy_fun_t) my_copy_function,
                            0,
                            ctxt,
                            (ht_check_copy_fun_t) my_check_copy_function,
                            src))) {
        return NULL;
    }

    /* the interfaces are populated at runtime using ADD_INTERFACE */
    dst->interfaces = NULL; 

    /* the current count includes inherited interfaces as well,
       the real dynamic ones are the first <n> which are zero'd
       out in zend_do_end_class_declaration */
    for(i = 0 ; (uint)i < src->num_interfaces ; i++) {
        if(src->interfaces[i])
        {
            dst->num_interfaces = i;
            break;
        }
    }

    /* these will either be set inside my_fixup_hashtable or 
     * they will be copied out from parent inside zend_do_inheritance 
     */
    dst->parent = NULL;
    dst->constructor =  NULL;
    dst->destructor = NULL;
    dst->clone = NULL;
    dst->__get = NULL;
    dst->__set = NULL;
    dst->__unset = NULL;
    dst->__isset = NULL;
    dst->__call = NULL;
#ifdef ZEND_ENGINE_2_2
    dst->__tostring = NULL;
#endif
#ifdef ZEND_ENGINE_2_3
	dst->__callstatic = NULL;
#endif

#ifdef ZEND_ENGINE_2_4
    if (src->trait_aliases) {
        int num_trait_aliases = 0;

        /* get how much trait aliases we've got */
        while (src->trait_aliases[num_trait_aliases]) {num_trait_aliases++;}

        /* copy all the trait aliases */
        CHECK(dst->trait_aliases =
                (zend_trait_alias **) apc_pool_alloc(pool, sizeof(zend_trait_alias *)*(num_trait_aliases+1)));

        i = 0;
        while (src->trait_aliases[i] && i < num_trait_aliases) {
            dst->trait_aliases[i] = apc_copy_trait_alias(NULL, src->trait_aliases[i], ctxt TSRMLS_CC);
            i++;
        }
        dst->trait_aliases[i] = NULL;
    }
    if (src->trait_precedences) {
        int num_trait_precedences = 0;

        /* get how much trait precedences we've got */
        while (src->trait_precedences[num_trait_precedences]) {num_trait_precedences++;}

        /* copy all the trait precedences */
        CHECK(dst->trait_precedences =
                (zend_trait_alias **) apc_pool_alloc(pool, sizeof(zend_trait_alias *)*(num_trait_precedences+1)));

        i = 0;
        while (src->trait_precedences[i] && i < num_trait_precedences) {
            dst->trait_precedences[i] = apc_copy_trait_precedence(NULL, src->trait_precedences[i], ctxt TSRMLS_CC);
            i++;
        }
        dst->trait_precedences[i] = NULL;
    }
#endif

    /* unset function proxies */
    dst->serialize_func = NULL;
    dst->unserialize_func = NULL;

    my_fixup_hashtable(&dst->function_table, (ht_fixup_fun_t)my_fixup_function, src, dst);

#ifdef ZEND_ENGINE_2_4
	dst->default_properties_count = src->default_properties_count;
    if (src->default_properties_count) {
        CHECK(dst->default_properties_table = (zval**) apc_pool_alloc(pool, (sizeof(zval*) * src->default_properties_count)));
        for (i = 0; i < src->default_properties_count; i++) {
            if (src->default_properties_table[i]) {
                my_copy_zval_ptr(&dst->default_properties_table[i], (const zval**)&src->default_properties_table[i], ctxt TSRMLS_CC);
            } else {
                dst->default_properties_table[i] = NULL;
            }
        }
    } else {
        dst->default_properties_table = NULL;
    }
#else
    memset(&dst->default_properties, 0, sizeof(dst->default_properties));
    CHECK((my_copy_hashtable_ex(&dst->default_properties,
                            &src->default_properties TSRMLS_CC,
                            (ht_copy_fun_t) my_copy_zval_ptr,
                            1,
                            ctxt,
                            (ht_check_copy_fun_t) my_check_copy_default_property,
                            src)));
#endif

    CHECK((my_copy_hashtable_ex(&dst->properties_info,
                            &src->properties_info TSRMLS_CC,
                            (ht_copy_fun_t) my_copy_property_info,
                            0,
                            ctxt,
                            (ht_check_copy_fun_t) my_check_copy_property_info,
                            src)));

#ifdef ZEND_ENGINE_2_2
    /* php5.2 introduced a scope attribute for property info */
    my_fixup_hashtable(&dst->properties_info, (ht_fixup_fun_t)my_fixup_property_info_for_execution, src, dst);
#endif

#ifdef ZEND_ENGINE_2_4
    dst->default_static_members_count = src->default_static_members_count;

    if (src->default_static_members_count) {
        CHECK(dst->default_static_members_table = (zval**) apc_pool_alloc(pool, (sizeof(zval*) * src->default_static_members_count)));
        for (i = 0; i < src->default_static_members_count; i++) {
            if (src->default_static_members_table[i]) {
                my_copy_zval_ptr(&dst->default_static_members_table[i], (const zval**)&src->default_static_members_table[i], ctxt TSRMLS_CC);
            } else {
                dst->default_static_members_table[i] = NULL;
            }
        }
    } else {
        dst->default_static_members_table = NULL;
    }
    dst->static_members_table = dst->default_static_members_table;
#else
    memset(&dst->default_static_members, 0, sizeof(dst->default_static_members));
    dst->static_members = NULL;
    CHECK(my_copy_hashtable_ex(&dst->default_static_members,
                            &src->default_static_members TSRMLS_CC,
                            (ht_copy_fun_t) my_copy_zval_ptr,
                            1,
                            ctxt,
                            (ht_check_copy_fun_t) my_check_copy_static_member,
                            src,
                            &src->default_static_members));

    if(src->static_members != &src->default_static_members)
    {
        CHECK((dst->static_members = my_copy_hashtable_ex(NULL,
                            src->static_members TSRMLS_CC,
                            (ht_copy_fun_t) my_copy_zval_ptr,
                            1,
                            ctxt,
                            (ht_check_copy_fun_t) my_check_copy_static_member,
                            src,
                            src->static_members)));
    }
    else
    {
        dst->static_members = &dst->default_static_members;
    }
#endif

    CHECK((my_copy_hashtable_ex(&dst->constants_table,
                            &src->constants_table TSRMLS_CC,
                            (ht_copy_fun_t) my_copy_zval_ptr,
                            1,
                            ctxt,
                            (ht_check_copy_fun_t) my_check_copy_constant,
                            src)));

    if (src->type == ZEND_USER_CLASS && ZEND_CE_DOC_COMMENT(src)) {
        CHECK(ZEND_CE_DOC_COMMENT(dst) =
                    apc_pmemcpy(ZEND_CE_DOC_COMMENT(src), (ZEND_CE_DOC_COMMENT_LEN(src) + 1), pool TSRMLS_CC));
    }

    if (src->type == ZEND_INTERNAL_CLASS && ZEND_CE_BUILTIN_FUNCTIONS(src)) {
        int n;

        for (n = 0; src->type == ZEND_INTERNAL_CLASS && ZEND_CE_BUILTIN_FUNCTIONS(src)[n].fname != NULL; n++) {}

        CHECK((ZEND_CE_BUILTIN_FUNCTIONS(dst) =
                (zend_function_entry*) apc_pool_alloc(pool, ((n + 1) * sizeof(zend_function_entry)))));

        for (i = 0; i < n; i++) {
            CHECK(my_copy_function_entry((zend_function_entry*)(&ZEND_CE_BUILTIN_FUNCTIONS(dst)[i]),
                                   &ZEND_CE_BUILTIN_FUNCTIONS(src)[i],
                                   ctxt TSRMLS_CC));
        }
        *(char**)&(ZEND_CE_BUILTIN_FUNCTIONS(dst)[n].fname) = NULL;
    }

    if (src->type == ZEND_USER_CLASS && ZEND_CE_FILENAME(src)) {
        CHECK((ZEND_CE_FILENAME(dst) = apc_pstrdup(ZEND_CE_FILENAME(src), pool TSRMLS_CC)));
    }

    return dst;
}
/* }}} */

/* {{{ my_free_hashtable */
static void my_free_hashtable(HashTable* ht, int type TSRMLS_DC)
{
    Bucket *curr = NULL;
    Bucket *prev = NULL;

    assert(ht != NULL);

    prev = ht->pListHead;
    while (prev != NULL) {
        curr = prev;
        prev = prev->pListNext;

#ifdef ZEND_ENGINE_2_4
        if (!IS_INTERNED(curr->arKey)) {
            apc_php_free((char*)curr->arKey TSRMLS_CC);
        } 
#else
        apc_php_free(curr->arKey TSRMLS_CC);
#endif
        switch (type) {
            case APC_FREE_HASHTABLE_FUNCS:
                do {
#if 0
                    /* XXX need to check where else the method is referenced,
                        the refcount leak is still there */
                    zend_function *fn;
                    fn = (zend_function *)curr->pData;

                    apc_free_op_array_after_execution(&fn->op_array TSRMLS_CC);
#endif
                    efree(curr->pData);
                } while (0);
                break;

            case APC_FREE_HASHTABLE_PROPS:
            case APC_FREE_HASHTABLE_STATIC_PROPS:
                efree(curr->pData);
                break;
        }

        /* XXX check if this must be ignored for any class method */
        if (type != APC_FREE_HASHTABLE_FUNCS) {
            apc_php_free(curr TSRMLS_CC);
        }
    }

    apc_php_free(ht->arBuckets TSRMLS_CC);
}
/* }}} */

/* {{{ my_copy_hashtable_ex */
static APC_HOTSPOT HashTable* my_copy_hashtable_ex(HashTable* dst,
                                    HashTable* src TSRMLS_DC,
                                    ht_copy_fun_t copy_fn,
                                    int holds_ptrs,
                                    apc_context_t* ctxt,
                                    ht_check_copy_fun_t check_fn,
                                    ...)
{
    Bucket* curr = NULL;
    Bucket* prev = NULL;
    Bucket* newp = NULL;
    int first = 1;
    apc_pool* pool = ctxt->pool;

    assert(src != NULL);

    if (!dst) {
        CHECK(dst = (HashTable*) apc_pool_alloc(pool, sizeof(src[0])));
    }

    memcpy(dst, src, sizeof(src[0]));

    /* allocate buckets for the new hashtable */
    CHECK((dst->arBuckets = apc_pool_alloc(pool, (dst->nTableSize * sizeof(Bucket*)))));

    memset(dst->arBuckets, 0, dst->nTableSize * sizeof(Bucket*));
    dst->pInternalPointer = NULL;
    dst->pListHead = NULL;

    for (curr = src->pListHead; curr != NULL; curr = curr->pListNext) {
        int n = curr->h % dst->nTableSize;

        if(check_fn) {
            va_list args;
            va_start(args, check_fn);

            /* Call the check_fn to see if the current bucket
             * needs to be copied out
             */
            if(!check_fn(curr, args)) {
                dst->nNumOfElements--;
                va_end(args);
                continue;
            }

            va_end(args);
        }

        /* create a copy of the bucket 'curr' */
#ifdef ZEND_ENGINE_2_4
        if (!curr->nKeyLength) {
            CHECK((newp = (Bucket*) apc_pmemcpy(curr, sizeof(Bucket), pool TSRMLS_CC)));
        } else if (IS_INTERNED(curr->arKey)) {
            CHECK((newp = (Bucket*) apc_pmemcpy(curr, sizeof(Bucket), pool TSRMLS_CC)));
#ifndef ZTS
        } else if (pool->type != APC_UNPOOL) {
            char *arKey;

            CHECK((newp = (Bucket*) apc_pmemcpy(curr, sizeof(Bucket), pool TSRMLS_CC)));
            arKey = (char *)apc_new_interned_string(curr->arKey, curr->nKeyLength TSRMLS_CC);
            if (!arKey) {
                CHECK((newp->arKey = (char*) apc_pmemcpy(curr->arKey, curr->nKeyLength, pool TSRMLS_CC)));
            } else {
                newp->arKey = arKey;
            }
#endif
        } else {
            CHECK((newp = (Bucket*) apc_pmemcpy(curr, sizeof(Bucket), pool TSRMLS_CC)));
            CHECK((newp->arKey = (char*) apc_pmemcpy(curr->arKey, curr->nKeyLength, pool TSRMLS_CC)));
        }
#else
        CHECK((newp = (Bucket*) apc_pmemcpy(curr,
                                  (sizeof(Bucket) + curr->nKeyLength - 1),
                                  pool TSRMLS_CC)));
#endif

        /* insert 'newp' into the linked list at its hashed index */
        if (dst->arBuckets[n]) {
            newp->pNext = dst->arBuckets[n];
            newp->pLast = NULL;
            newp->pNext->pLast = newp;
        }
        else {
            newp->pNext = newp->pLast = NULL;
        }

        dst->arBuckets[n] = newp;

        /* copy the bucket data using our 'copy_fn' callback function */
        CHECK((newp->pData = copy_fn(NULL, curr->pData, ctxt TSRMLS_CC)));

        if (holds_ptrs) {
            memcpy(&newp->pDataPtr, newp->pData, sizeof(void*));
        }
        else {
            newp->pDataPtr = NULL;
        }

        /* insert 'newp' into the table-thread linked list */
        newp->pListLast = prev;
        newp->pListNext = NULL;

        if (prev) {
            prev->pListNext = newp;
        }

        if (first) {
            dst->pListHead = newp;
            first = 0;
        }

        prev = newp;
    }

    dst->pListTail = newp;

    zend_hash_internal_pointer_reset(dst);

    return dst;
}
/* }}} */

/* {{{ my_copy_static_variables */
static HashTable* my_copy_static_variables(zend_op_array* src, apc_context_t* ctxt TSRMLS_DC)
{
    if (src->static_variables == NULL) {
        return NULL;
    }

    return my_copy_hashtable(NULL,
                             src->static_variables,
                             (ht_copy_fun_t) my_copy_zval_ptr,
                             1,
                             ctxt);
}
/* }}} */

/* {{{ apc_copy_zval */
zval* apc_copy_zval(zval* dst, const zval* src, apc_context_t* ctxt TSRMLS_DC)
{
    apc_pool* pool = ctxt->pool;
    int usegc = (ctxt->copy == APC_COPY_OUT_OPCODE) || (ctxt->copy == APC_COPY_OUT_USER);

    assert(src != NULL);

    if (!dst) {
        if(usegc) {
            ALLOC_ZVAL(dst);
            CHECK(dst);
        } else {
            CHECK(dst = (zval*) apc_pool_alloc(pool, sizeof(zval)));
        }
    }

    CHECK(dst = my_copy_zval(dst, src, ctxt TSRMLS_CC));
    return dst;
}
/* }}} */

/* {{{ apc_fixup_op_array_jumps */
static void apc_fixup_op_array_jumps(zend_op_array *dst, zend_op_array *src )
{
    uint i;

    for (i=0; i < dst->last; ++i) {
        zend_op *zo = &(dst->opcodes[i]);
        /*convert opline number to jump address*/
        switch (zo->opcode) {
#ifdef ZEND_ENGINE_2_3
            case ZEND_GOTO:
#endif
            case ZEND_JMP:
                /*Note: if src->opcodes != dst->opcodes then we need to the opline according to src*/
#ifdef ZEND_ENGINE_2_4
                zo->op1.jmp_addr = dst->opcodes + (zo->op1.jmp_addr - src->opcodes);
#else
                zo->op1.u.jmp_addr = dst->opcodes + (zo->op1.u.jmp_addr - src->opcodes);
#endif
                break;
            case ZEND_JMPZ:
            case ZEND_JMPNZ:
            case ZEND_JMPZ_EX:
            case ZEND_JMPNZ_EX:
#ifdef ZEND_ENGINE_2_3
            case ZEND_JMP_SET:
#endif
#ifdef ZEND_ENGINE_2_4
            case ZEND_JMP_SET_VAR:
#endif
#ifdef ZEND_ENGINE_2_4
                zo->op2.jmp_addr = dst->opcodes + (zo->op2.jmp_addr - src->opcodes);
#else
                zo->op2.u.jmp_addr = dst->opcodes + (zo->op2.u.jmp_addr - src->opcodes);
#endif
                break;
            default:
                break;
        }
    }
}
/* }}} */

/* {{{ apc_copy_op_array */
zend_op_array* apc_copy_op_array(zend_op_array* dst, zend_op_array* src, apc_context_t* ctxt TSRMLS_DC)
{
    int i;
    apc_fileinfo_t *fileinfo = NULL;
    char canon_path[MAXPATHLEN];
    char *fullpath = NULL;
    apc_opflags_t * flags = NULL;
    apc_pool* pool = ctxt->pool;

    assert(src != NULL);

    if (!dst) {
        CHECK(dst = (zend_op_array*) apc_pool_alloc(pool, sizeof(src[0])));
    }

    if(APCG(apc_optimize_function)) {
        APCG(apc_optimize_function)(src TSRMLS_CC);
    }

    /* start with a bitwise copy of the array */
    memcpy(dst, src, sizeof(src[0]));

    dst->function_name = NULL;
    dst->filename = NULL;
    dst->refcount = NULL;
    dst->opcodes = NULL;
    dst->brk_cont_array = NULL;
    dst->static_variables = NULL;
    dst->try_catch_array = NULL;
    dst->arg_info = NULL;
    dst->doc_comment = NULL;
#ifdef ZEND_ENGINE_2_1
    dst->vars = NULL;
#endif

    /* copy the arg types array (if set) */
    if (src->arg_info) {
        CHECK(dst->arg_info = my_copy_arg_info_array(NULL,
                                                src->arg_info,
                                                src->num_args,
                                                ctxt TSRMLS_CC));
    }

    if (src->function_name) {
        CHECK(dst->function_name = apc_pstrdup(src->function_name, pool TSRMLS_CC));
    }
    if (src->filename) {
        CHECK(dst->filename = apc_pstrdup(src->filename, pool TSRMLS_CC));
    }

    CHECK(dst->refcount = apc_pmemcpy(src->refcount,
                                      sizeof(src->refcount[0]),
                                      pool TSRMLS_CC));

#ifdef ZEND_ENGINE_2_4
    if (src->literals) {
        zend_literal *p, *q, *end;

        q = src->literals;
        p = dst->literals = (zend_literal*) apc_pool_alloc(pool, (sizeof(zend_literal) * src->last_literal));
        end = p + src->last_literal;
        while (p < end) {
            *p = *q;
            my_copy_zval(&p->constant, &q->constant, ctxt TSRMLS_CC);
            p++;
            q++;
        }
    }
#endif

    /* deep-copy the opcodes */
    CHECK(dst->opcodes = (zend_op*) apc_pool_alloc(pool, (sizeof(zend_op) * src->last)));

    if(apc_reserved_offset != -1) {
        /* Insanity alert: the void* pointer is cast into an apc_opflags_t 
         * struct. apc_zend_init() checks to ensure that it fits in a void* */
        flags = (apc_opflags_t*) & (dst->reserved[apc_reserved_offset]);
        memset(flags, 0, sizeof(apc_opflags_t));
        /* assert(sizeof(apc_opflags_t) <= sizeof(dst->reserved)); */
    }

    for (i = 0; (uint) i < src->last; i++) {
        zend_op *zo = &(src->opcodes[i]);
        /* a lot of files are merely constant arrays with no jumps */
        switch (zo->opcode) {
#ifdef ZEND_ENGINE_2_3
            case ZEND_GOTO:
#endif
            case ZEND_JMP:
            case ZEND_JMPZ:
            case ZEND_JMPNZ:
            case ZEND_JMPZ_EX:
            case ZEND_JMPNZ_EX:
#ifdef ZEND_ENGINE_2_3
            case ZEND_JMP_SET:
#endif
#ifdef ZEND_ENGINE_2_4
            case ZEND_JMP_SET_VAR:
#endif
                if(flags != NULL) {
                    flags->has_jumps = 1;
                }
                break;
            /* auto_globals_jit was not in php-4.3.* */
            case ZEND_FETCH_R:
            case ZEND_FETCH_W:
            case ZEND_FETCH_IS:
            case ZEND_FETCH_FUNC_ARG:
            case ZEND_FETCH_RW:
            case ZEND_FETCH_UNSET:
                if(PG(auto_globals_jit) && flags != NULL)
                {
                     /* The fetch is only required if auto_globals_jit=1  */
#ifdef ZEND_ENGINE_2_4
                    if((zo->extended_value & ZEND_FETCH_TYPE_MASK) == ZEND_FETCH_GLOBAL &&
                            zo->op1_type == IS_CONST && 
                            Z_TYPE_P(zo->op1.zv) == IS_STRING) {
                        if (Z_STRVAL_P(zo->op1.zv)[0] == '_') {
# define SET_IF_AUTOGLOBAL(member) \
    if(!strcmp(Z_STRVAL_P(zo->op1.zv), #member)) \
        flags->member = 1 /* no ';' here */
#else
                    if(zo->op2.u.EA.type == ZEND_FETCH_GLOBAL &&
                            zo->op1.op_type == IS_CONST && 
                            zo->op1.u.constant.type == IS_STRING) {
                        znode * varname = &zo->op1;
                        if (varname->u.constant.value.str.val[0] == '_') {
# define SET_IF_AUTOGLOBAL(member) \
    if(!strcmp(varname->u.constant.value.str.val, #member)) \
        flags->member = 1 /* no ';' here */
#endif
                            SET_IF_AUTOGLOBAL(_GET);
                            else SET_IF_AUTOGLOBAL(_POST);
                            else SET_IF_AUTOGLOBAL(_COOKIE);
                            else SET_IF_AUTOGLOBAL(_SERVER);
                            else SET_IF_AUTOGLOBAL(_ENV);
                            else SET_IF_AUTOGLOBAL(_FILES);
                            else SET_IF_AUTOGLOBAL(_REQUEST);
                            else SET_IF_AUTOGLOBAL(_SESSION);
#ifdef ZEND_ENGINE_2_4
                            else if(zend_is_auto_global(
                                            Z_STRVAL_P(zo->op1.zv),
                                            Z_STRLEN_P(zo->op1.zv)
                                            TSRMLS_CC))
#else
                            else if(zend_is_auto_global(
                                            varname->u.constant.value.str.val,
                                            varname->u.constant.value.str.len
                                            TSRMLS_CC))
#endif
                            {
                                flags->unknown_global = 1;
                            }
#ifdef ZEND_ENGINE_2_4
                        } else SET_IF_AUTOGLOBAL(GLOBALS);
#else
                        }
#endif
                    }
                }
                break;
            case ZEND_RECV_INIT:
#ifdef ZEND_ENGINE_2_4
                if(zo->op2_type == IS_CONST &&
                    Z_TYPE_P(zo->op2.zv) == IS_CONSTANT_ARRAY) {
#else
                if(zo->op2.op_type == IS_CONST &&
                    zo->op2.u.constant.type == IS_CONSTANT_ARRAY) {
#endif
                    if(flags != NULL) {
                        flags->deep_copy = 1;
                    }
                }
                break;
            default:
#ifdef ZEND_ENGINE_2_4
                if((zo->op1_type == IS_CONST &&
                    Z_TYPE_P(zo->op1.zv) == IS_CONSTANT_ARRAY) ||
                    (zo->op2_type == IS_CONST &&
                        Z_TYPE_P(zo->op2.zv) == IS_CONSTANT_ARRAY)) {
#else
                if((zo->op1.op_type == IS_CONST &&
                    zo->op1.u.constant.type == IS_CONSTANT_ARRAY) ||
                    (zo->op2.op_type == IS_CONST &&
                        zo->op2.u.constant.type == IS_CONSTANT_ARRAY)) {
#endif
                    if(flags != NULL) {
                        flags->deep_copy = 1;
                    }
                }
                break;
        }

        if(!(my_copy_zend_op(dst->opcodes+i, src->opcodes+i, ctxt TSRMLS_CC))) {
            return NULL;
        }

#ifdef ZEND_ENGINE_2_4
        if (zo->op1_type == IS_CONST) {
            dst->opcodes[i].op1.literal = src->opcodes[i].op1.literal - src->literals + dst->literals;
        }
        if (zo->op2_type == IS_CONST) {
            dst->opcodes[i].op2.literal = src->opcodes[i].op2.literal - src->literals + dst->literals;
        }
        if (zo->result_type == IS_CONST) {
            dst->opcodes[i].result.literal = src->opcodes[i].result.literal - src->literals + dst->literals;
        }
#endif

        /* This code breaks apc's rule#1 - cache what you compile */
        if((APCG(fpstat)==0) && APCG(canonicalize)) {
            /* not pool allocated, because the pool allocations eat up shm space */
            fileinfo = (apc_fileinfo_t*) apc_php_malloc(sizeof(apc_fileinfo_t) TSRMLS_CC);
#ifdef ZEND_ENGINE_2_4
            if((zo->opcode == ZEND_INCLUDE_OR_EVAL) && 
                (zo->op1_type == IS_CONST && Z_TYPE_P(zo->op1.zv) == IS_STRING)) {
                /* constant includes */
                if(!IS_ABSOLUTE_PATH(Z_STRVAL_P(zo->op1.zv),Z_STRLEN_P(zo->op1.zv))) { 
                    if (apc_search_paths(Z_STRVAL_P(zo->op1.zv), PG(include_path), fileinfo TSRMLS_CC) == 0) {
#else
            if((zo->opcode == ZEND_INCLUDE_OR_EVAL) && 
                (zo->op1.op_type == IS_CONST && zo->op1.u.constant.type == IS_STRING)) {
                /* constant includes */
                if(!IS_ABSOLUTE_PATH(Z_STRVAL_P(&zo->op1.u.constant),Z_STRLEN_P(&zo->op1.u.constant))) { 
                    if (apc_search_paths(Z_STRVAL_P(&zo->op1.u.constant), PG(include_path), fileinfo TSRMLS_CC) == 0) {
#endif
                        if((fullpath = realpath(fileinfo->fullpath, canon_path))) {
                            /* everything has to go through a realpath() */
                            zend_op *dzo = &(dst->opcodes[i]);
#ifdef ZEND_ENGINE_2_4
                            dzo->op1.literal = (zend_literal*) apc_pool_alloc(pool, sizeof(zend_literal));
                            Z_STRLEN_P(dzo->op1.zv) = strlen(fullpath);
                            Z_STRVAL_P(dzo->op1.zv) = apc_pstrdup(fullpath, pool TSRMLS_CC);
                            Z_TYPE_P(dzo->op1.zv) = IS_STRING;
                            Z_SET_REFCOUNT_P(dzo->op1.zv, 2);
                            Z_SET_ISREF_P(dzo->op1.zv);
                            dzo->op1.literal->hash_value = zend_hash_func(Z_STRVAL_P(dzo->op1.zv), Z_STRLEN_P(dzo->op1.zv)+1);
#else
                            dzo->op1.u.constant.value.str.len = strlen(fullpath);
                            dzo->op1.u.constant.value.str.val = apc_pstrdup(fullpath, pool TSRMLS_CC);
#endif
                        }
                    }
                }
            }
            apc_php_free(fileinfo TSRMLS_CC);
        }
    }

    if(flags == NULL || flags->has_jumps) {
        apc_fixup_op_array_jumps(dst,src);
    }

    /* copy the break-continue array */
    if (src->brk_cont_array) {
        CHECK(dst->brk_cont_array = apc_pmemcpy(src->brk_cont_array,
                                    sizeof(src->brk_cont_array[0]) * src->last_brk_cont,
                                    pool TSRMLS_CC));
    }

    /* copy the table of static variables */
    if (src->static_variables) {
        CHECK(dst->static_variables = my_copy_static_variables(src, ctxt TSRMLS_CC));
    }

    if (src->try_catch_array) {
        CHECK(dst->try_catch_array = apc_pmemcpy(src->try_catch_array,
                                        sizeof(src->try_catch_array[0]) * src->last_try_catch,
                                        pool TSRMLS_CC));
    }

#ifdef ZEND_ENGINE_2_1 /* PHP 5.1 */
    if (src->vars) {
        CHECK(dst->vars = apc_pmemcpy(src->vars,
                            sizeof(src->vars[0]) * src->last_var,
                            pool TSRMLS_CC));

        for(i = 0; i <  src->last_var; i++) dst->vars[i].name = NULL;

        for(i = 0; i <  src->last_var; i++) {
            CHECK(dst->vars[i].name = apc_string_pmemcpy((char *)src->vars[i].name,
                                src->vars[i].name_len + 1,
                                pool TSRMLS_CC));
        }
    }
#endif

    if (src->doc_comment) {
        CHECK(dst->doc_comment
                = apc_pmemcpy(src->doc_comment, (src->doc_comment_len + 1), pool TSRMLS_CC));
    }

    return dst;
}
/* }}} */

/* {{{ apc_copy_new_functions */
apc_function_t* apc_copy_new_functions(int old_count, apc_context_t* ctxt TSRMLS_DC)
{
    apc_function_t* array;
    int new_count;              /* number of new functions in table */
    int i;
    apc_pool* pool = ctxt->pool;

    new_count = zend_hash_num_elements(CG(function_table)) - old_count;
    assert(new_count >= 0);

    CHECK(array =
        (apc_function_t*)
            apc_pool_alloc(pool, (sizeof(apc_function_t) * (new_count + 1))));

    if (new_count == 0) {
        array[0].function = NULL;
        return array;
    }

    /* Skip the first `old_count` functions in the table */
    zend_hash_internal_pointer_reset(CG(function_table));
    for (i = 0; i < old_count; i++) {
        zend_hash_move_forward(CG(function_table));
    }

    /* Add the next `new_count` functions to our array */
    for (i = 0; i < new_count; i++) {
        char* key;
        uint key_size;
        zend_function* fun;

        zend_hash_get_current_key_ex(CG(function_table),
                                     &key,
                                     &key_size,
                                     NULL,
                                     0,
                                     NULL);

        zend_hash_get_current_data(CG(function_table), (void**) &fun);

        CHECK(array[i].name = apc_pmemcpy(key, (int) key_size, pool TSRMLS_CC));
        array[i].name_len = (int) key_size-1;
        CHECK(array[i].function = my_copy_function(NULL, fun, ctxt TSRMLS_CC));
        zend_hash_move_forward(CG(function_table));
    }

    array[i].function = NULL;
    return array;
}
/* }}} */

/* {{{ apc_copy_new_classes */
apc_class_t* apc_copy_new_classes(zend_op_array* op_array, int old_count, apc_context_t *ctxt TSRMLS_DC)
{
    apc_class_t* array;
    int new_count;              /* number of new classes in table */
    int i;
    apc_pool* pool = ctxt->pool;

    new_count = zend_hash_num_elements(CG(class_table)) - old_count;
    assert(new_count >= 0);

    CHECK(array =
        (apc_class_t*)
            apc_pool_alloc(pool, (sizeof(apc_class_t) * (new_count + 1))));

    if (new_count == 0) {
        array[0].class_entry = NULL;
        return array;
    }

    /* Skip the first `old_count` classes in the table */
    zend_hash_internal_pointer_reset(CG(class_table));
    for (i = 0; i < old_count; i++) {
        zend_hash_move_forward(CG(class_table));
    }

    /* Add the next `new_count` classes to our array */
    for (i = 0; i < new_count; i++) {
        char* key;
        uint key_size;
        zend_class_entry* elem = NULL;

        array[i].class_entry = NULL;

        zend_hash_get_current_key_ex(CG(class_table),
                                     &key,
                                     &key_size,
                                     NULL,
                                     0,
                                     NULL);

        zend_hash_get_current_data(CG(class_table), (void**) &elem);


        elem = *((zend_class_entry**)elem);

        CHECK(array[i].name = apc_pmemcpy(key, (int) key_size, pool TSRMLS_CC));
        array[i].name_len = (int) key_size-1;
        CHECK(array[i].class_entry = my_copy_class_entry(NULL, elem, ctxt TSRMLS_CC));

        /*
         * If the class has a pointer to its parent class, save the parent
         * name so that we can enable compile-time inheritance when we reload
         * the child class; otherwise, set the parent name to null and scan
         * the op_array to determine if this class inherits from some base
         * class at execution-time.
         */

        if (elem->parent) {
            CHECK(array[i].parent_name = apc_pstrdup(elem->parent->name, pool TSRMLS_CC));
        }
        else {
            array[i].parent_name = NULL;
        }

        zend_hash_move_forward(CG(class_table));
    }

    array[i].class_entry = NULL;
    return array;
}
/* }}} */

/* Used only by my_prepare_op_array_for_execution */
#ifdef ZEND_ENGINE_2_4
# define APC_PREPARE_FETCH_GLOBAL_FOR_EXECUTION()                                               \
                         /* The fetch is only required if auto_globals_jit=1  */                \
                        if((zo->extended_value & ZEND_FETCH_TYPE_MASK) == ZEND_FETCH_GLOBAL &&    \
                            zo->op1_type == IS_CONST &&                                         \
                            Z_TYPE_P(zo->op1.zv) == IS_STRING &&                                \
                            Z_STRVAL_P(zo->op1.zv)[0] == '_') {                                 \
                            (void)zend_is_auto_global(Z_STRVAL_P(zo->op1.zv),                   \
                                                      Z_STRLEN_P(zo->op1.zv)                    \
                                                      TSRMLS_CC);                               \
                        }
#else
# define APC_PREPARE_FETCH_GLOBAL_FOR_EXECUTION()                                               \
                         /* The fetch is only required if auto_globals_jit=1  */                \
                        if(zo->op2.u.EA.type == ZEND_FETCH_GLOBAL &&                            \
                            zo->op1.op_type == IS_CONST &&                                      \
                            zo->op1.u.constant.type == IS_STRING &&                             \
                            zo->op1.u.constant.value.str.val[0] == '_') {                       \
                                                                                                \
                            znode* varname = &zo->op1;                                          \
                            (void)zend_is_auto_global(varname->u.constant.value.str.val,        \
                                                          varname->u.constant.value.str.len     \
                                                          TSRMLS_CC);                           \
                        }
#endif

/* {{{ my_prepare_op_array_for_execution */
static int my_prepare_op_array_for_execution(zend_op_array* dst, zend_op_array* src, apc_context_t* ctxt TSRMLS_DC) 
{
    /* combine my_fetch_global_vars and my_copy_data_exceptions.
     *   - Pre-fetch superglobals which would've been pre-fetched in parse phase.
     *   - If the opcode stream contain mutable data, ensure a copy.
     *   - Fixup array jumps in the same loop.
     */
    int i=src->last;
    zend_op *zo;
    zend_op *dzo;
    apc_opflags_t * flags = apc_reserved_offset  != -1 ? 
                                (apc_opflags_t*) & (src->reserved[apc_reserved_offset]) : NULL;
    int needcopy = flags ? flags->deep_copy : 1;
    /* auto_globals_jit was not in php4 */
    int do_prepare_fetch_global = PG(auto_globals_jit) && (flags == NULL || flags->unknown_global);

#define FETCH_AUTOGLOBAL(member) do { \
    if(flags && flags->member == 1) { \
        zend_is_auto_global(#member,\
                            (sizeof(#member) - 1)\
                            TSRMLS_CC);\
    } \
} while(0);

    FETCH_AUTOGLOBAL(_GET);
    FETCH_AUTOGLOBAL(_POST);
    FETCH_AUTOGLOBAL(_COOKIE);
    FETCH_AUTOGLOBAL(_SERVER);
    FETCH_AUTOGLOBAL(_ENV);
    FETCH_AUTOGLOBAL(_FILES);
    FETCH_AUTOGLOBAL(_REQUEST);
    FETCH_AUTOGLOBAL(_SESSION);
#ifdef ZEND_ENGINE_2_4
    FETCH_AUTOGLOBAL(GLOBALS);
#endif

    if(needcopy) {

#ifdef ZEND_ENGINE_2_4
        if (src->literals) {
            zend_literal *p, *q, *end;

            q = src->literals;
            p = dst->literals = (zend_literal*) apc_xmemcpy(src->literals,
                                        sizeof(zend_literal) * src->last_literal,
                                        apc_php_malloc TSRMLS_CC);
            end = p + src->last_literal;
            while (p < end) {
                if (Z_TYPE(q->constant) == IS_CONSTANT_ARRAY) {
                    my_copy_zval(&p->constant, &q->constant, ctxt TSRMLS_CC);
                }
                p++;
                q++;
            }
        }
#endif

        dst->opcodes = (zend_op*) apc_xmemcpy(src->opcodes,
                                    sizeof(zend_op) * src->last,
                                    apc_php_malloc TSRMLS_CC);
        zo = src->opcodes;
        dzo = dst->opcodes;
        while(i > 0) {

#ifdef ZEND_ENGINE_2_4
            if(zo->op1_type == IS_CONST) {
               dzo->op1.literal = zo->op1.literal - src->literals + dst->literals;
            }
            if(zo->op2_type == IS_CONST) {
               dzo->op2.literal = zo->op2.literal - src->literals + dst->literals;
            }
            if(zo->result_type == IS_CONST) {
               dzo->result.literal = zo->result.literal - src->literals + dst->literals;
            }
#else
            if( ((zo->op1.op_type == IS_CONST &&
                  zo->op1.u.constant.type == IS_CONSTANT_ARRAY)) ||
                ((zo->op2.op_type == IS_CONST &&
                  zo->op2.u.constant.type == IS_CONSTANT_ARRAY))) {

                if(!(my_copy_zend_op(dzo, zo, ctxt TSRMLS_CC))) {
                    assert(0); /* emalloc failed or a bad constant array */
                }
            }
#endif

            switch(zo->opcode) {
#ifdef ZEND_ENGINE_2_3
                case ZEND_GOTO:
#endif
                case ZEND_JMP:
#ifdef ZEND_ENGINE_2_4
                    dzo->op1.jmp_addr = dst->opcodes +
                                            (zo->op1.jmp_addr - src->opcodes);
#else
                    dzo->op1.u.jmp_addr = dst->opcodes +
                                            (zo->op1.u.jmp_addr - src->opcodes);
#endif
                    break;
                case ZEND_JMPZ:
                case ZEND_JMPNZ:
                case ZEND_JMPZ_EX:
                case ZEND_JMPNZ_EX:
#ifdef ZEND_ENGINE_2_3
                case ZEND_JMP_SET:
#endif
#ifdef ZEND_ENGINE_2_4
                case ZEND_JMP_SET_VAR:
#endif
#ifdef ZEND_ENGINE_2_4
                    dzo->op2.jmp_addr = dst->opcodes +
                                            (zo->op2.jmp_addr - src->opcodes);
#else
                    dzo->op2.u.jmp_addr = dst->opcodes +
                                            (zo->op2.u.jmp_addr - src->opcodes);
#endif
                    break;
                case ZEND_FETCH_R:
                case ZEND_FETCH_W:
                case ZEND_FETCH_IS:
                case ZEND_FETCH_FUNC_ARG:
                    if(do_prepare_fetch_global)
                    {
                        APC_PREPARE_FETCH_GLOBAL_FOR_EXECUTION();
                    }
                    break;
                default:
                    break;
            }
            i--;
            zo++;
            dzo++;
        }
    } else {  /* !needcopy */
        /* The fetch is only required if auto_globals_jit=1  */
        if(do_prepare_fetch_global)
        {
            zo = src->opcodes;
            while(i > 0) {

                if(zo->opcode == ZEND_FETCH_R ||
                   zo->opcode == ZEND_FETCH_W ||
                   zo->opcode == ZEND_FETCH_IS ||
                   zo->opcode == ZEND_FETCH_FUNC_ARG
                  ) {
                    APC_PREPARE_FETCH_GLOBAL_FOR_EXECUTION();
                }

                i--;
                zo++;
            }
        }
    }
    return 1;
}
/* }}} */

/* {{{ apc_copy_op_array_for_execution */
zend_op_array* apc_copy_op_array_for_execution(zend_op_array* dst, zend_op_array* src, apc_context_t* ctxt TSRMLS_DC)
{
    if(dst == NULL) {
        dst = (zend_op_array*) emalloc(sizeof(src[0]));
    }
    memcpy(dst, src, sizeof(src[0]));
    dst->static_variables = my_copy_static_variables(src, ctxt TSRMLS_CC);

    dst->refcount = apc_pmemcpy(src->refcount,
                                      sizeof(src->refcount[0]),
                                      ctxt->pool TSRMLS_CC);

    my_prepare_op_array_for_execution(dst,src, ctxt TSRMLS_CC);

    return dst;
}
/* }}} */

/* {{{ apc_free_op_array_after_execution */
void apc_free_op_array_after_execution(zend_op_array *src TSRMLS_DC)
{
    if (NULL != src->refcount) {
        apc_php_free(src->refcount TSRMLS_CC);
    }
}
/* }}} */

/* {{{ apc_copy_function_for_execution */
zend_function* apc_copy_function_for_execution(zend_function* src, apc_context_t* ctxt TSRMLS_DC)
{
    zend_function* dst;

    dst = (zend_function*) emalloc(sizeof(src[0]));
    memcpy(dst, src, sizeof(src[0]));
    apc_copy_op_array_for_execution(&(dst->op_array), &(src->op_array), ctxt TSRMLS_CC);
    return dst;
}
/* }}} */

/* {{{ apc_copy_function_for_execution_ex */
zend_function* apc_copy_function_for_execution_ex(void *dummy, zend_function* src, apc_context_t* ctxt TSRMLS_DC)
{
    if(src->type==ZEND_INTERNAL_FUNCTION || src->type==ZEND_OVERLOADED_FUNCTION) {
        return src;
    }

    return apc_copy_function_for_execution(src, ctxt TSRMLS_CC);
}
/* }}} */

/* {{{ apc_free_function_after_execution */
void apc_free_function_after_execution(zend_function* src TSRMLS_DC)
{
    if(src->type==ZEND_INTERNAL_FUNCTION || src->type==ZEND_OVERLOADED_FUNCTION) {
        return;
    }

    apc_free_op_array_after_execution(&src->op_array TSRMLS_CC);
}
/* }}} */

/* {{{ apc_copy_class_entry_for_execution */
zend_class_entry* apc_copy_class_entry_for_execution(zend_class_entry* src, apc_context_t* ctxt TSRMLS_DC)
{
#ifdef ZEND_ENGINE_2_4
    int i;
#endif
    zend_class_entry* dst = (zend_class_entry*) apc_pool_alloc(ctxt->pool, sizeof(src[0]));
    memcpy(dst, src, sizeof(src[0]));

    if(src->num_interfaces)
    {
        /* These are slots to be populated later by ADD_INTERFACE insns */
        dst->interfaces = apc_php_malloc(
                            (sizeof(zend_class_entry*) * src->num_interfaces) TSRMLS_CC);
        memset(dst->interfaces, 0, 
                            sizeof(zend_class_entry*) * src->num_interfaces);
    }
    else
    {
        /* assert(dst->interfaces == NULL); */
    }

    /* Deep-copy the class properties, because they will be modified */

#ifdef ZEND_ENGINE_2_4
    dst->name = apc_string_pmemcpy((char*)src->name, src->name_length+1, ctxt->pool TSRMLS_CC); 
	dst->default_properties_count = src->default_properties_count;
    if (src->default_properties_count) {
        dst->default_properties_table = (zval**) apc_php_malloc((sizeof(zval*) * src->default_properties_count) TSRMLS_CC);
        for (i = 0; i < src->default_properties_count; i++) {
            if (src->default_properties_table[i]) {
                my_copy_zval_ptr(&dst->default_properties_table[i], (const zval**)&src->default_properties_table[i], ctxt TSRMLS_CC);
            } else {
                dst->default_properties_table[i] = NULL;
            }
        }
    } else {
        dst->default_properties_table = NULL;
    }
#else
    my_copy_hashtable(&dst->default_properties,
                      &src->default_properties,
                      (ht_copy_fun_t) my_copy_zval_ptr,
                      1,
                      ctxt);
#endif

    /* For derived classes, we must also copy the function hashtable (although
     * we can merely bitwise copy the functions it contains) */
    my_copy_hashtable(&dst->function_table,
                      &src->function_table,
                      (ht_copy_fun_t) apc_copy_function_for_execution_ex,
                      0,
                      ctxt);

    my_fixup_hashtable(&dst->function_table, (ht_fixup_fun_t)my_fixup_function_for_execution, src, dst);

    /* zend_do_inheritance merges properties_info.
     * Need only shallow copying as it doesn't hold the pointers.
     */
    my_copy_hashtable(&dst->properties_info,
                      &src->properties_info,
                      (ht_copy_fun_t) my_copy_property_info_for_execution,
                      0,
                      ctxt);

#ifdef ZEND_ENGINE_2_2
    /* php5.2 introduced a scope attribute for property info */
    my_fixup_hashtable(&dst->properties_info, (ht_fixup_fun_t)my_fixup_property_info_for_execution, src, dst);
#endif

    /* if inheritance results in a hash_del, it might result in
     * a pefree() of the pointers here. Deep copying required. 
     */

    my_copy_hashtable(&dst->constants_table,
                      &src->constants_table,
                      (ht_copy_fun_t) my_copy_zval_ptr,
                      1,
                      ctxt);

#ifdef ZEND_ENGINE_2_4
	dst->default_static_members_count = src->default_static_members_count;
    if (src->default_static_members_count) {
        dst->default_static_members_table = (zval**) apc_php_malloc((sizeof(zval*) * src->default_static_members_count) TSRMLS_CC);
        for (i = 0; i < src->default_static_members_count; i++) {
            if (src->default_static_members_table[i]) {
                my_copy_zval_ptr(&dst->default_static_members_table[i], (const zval**)&src->default_static_members_table[i], ctxt TSRMLS_CC);
            } else {
                dst->default_static_members_table[i] = NULL;
            }
        }
    } else {
        dst->default_static_members_table = NULL;
    }
    dst->static_members_table = dst->default_static_members_table;
#else
    my_copy_hashtable(&dst->default_static_members,
                      &src->default_static_members,
                      (ht_copy_fun_t) my_copy_zval_ptr,
                      1,
                      ctxt);

    if(src->static_members != &(src->default_static_members))
    {
        dst->static_members = my_copy_hashtable(NULL,
                          src->static_members,
                          (ht_copy_fun_t) my_copy_zval_ptr,
                          1,
                          ctxt);
    }
    else 
    {
        dst->static_members = &(dst->default_static_members);
    }
#endif

#ifdef ZEND_ENGINE_2_4
    if (src->trait_aliases) {
        int num_trait_aliases = 0;

        /* get how much trait aliases we've got */
        while (src->trait_aliases[num_trait_aliases]) {num_trait_aliases++;}

        /* copy all the trait aliases */
        CHECK(dst->trait_aliases = (zend_trait_alias **) apc_pool_alloc(ctxt->pool, sizeof(zend_trait_alias *)*(num_trait_aliases+1)));
        i = 0;
        while (src->trait_aliases[i]) {
            dst->trait_aliases[i] = apc_copy_trait_alias_for_execution(src->trait_aliases[i], ctxt TSRMLS_CC);
            i++;
        }
        dst->trait_aliases[i] = NULL;
    } 
    if (src->trait_precedences) {
        int num_trait_precedences = 0;

        /* get how much trait precedences we've got */
        while (src->trait_precedences[num_trait_precedences]) {num_trait_precedences++;}

        /* copy all the trait precedences */
        CHECK(dst->trait_precedences = 
                (zend_trait_alias **) apc_pool_alloc(ctxt->pool, sizeof(zend_trait_alias *)*(num_trait_precedences+1)));
        i = 0;
        while (src->trait_precedences[i]) {
            dst->trait_precedences[i] =
                apc_copy_trait_precedence_for_execution(src->trait_precedences[i], ctxt TSRMLS_CC);
            i++;
        }
        dst->trait_precedences[i] = NULL;
    } 
#endif

    return dst;
}
/* }}} */

/* {{{ apc_free_class_entry_after_execution */
void apc_free_class_entry_after_execution(zend_class_entry* src TSRMLS_DC)
{
    if(src->num_interfaces > 0 && src->interfaces) {
        apc_php_free(src->interfaces TSRMLS_CC);
        src->interfaces = NULL;
        src->num_interfaces = 0;
    }
    /* my_destroy_hashtable() does not play nice with refcounts */

#ifdef ZEND_ENGINE_2_4
#if 0
    if (!IS_INTERNED(src->name)) {
        apc_php_free(src->name TSRMLS_CC);
    }
#endif
    if (src->default_static_members_table) {
       int i;

       for (i = 0; i < src->default_static_members_count; i++) {
          zval_ptr_dtor(&src->default_static_members_table[i]);
       }
       efree(src->default_static_members_table);
       src->default_static_members_table = NULL;
    }
    src->static_members_table = NULL;
    if (src->default_properties_table) {
       int i;

       for (i = 0; i < src->default_properties_count; i++) {
           if (src->default_properties_table[i]) {
               zval_ptr_dtor(&src->default_properties_table[i]);
           }
       }
       efree(src->default_properties_table);
       src->default_properties_table = NULL;
    }
#else
    zend_hash_clean(&src->default_static_members);
    if(src->static_members != &(src->default_static_members))
    {
        zend_hash_destroy(src->static_members);
        apc_php_free(src->static_members TSRMLS_CC);
        src->static_members = NULL;
    }
    else
    {
        src->static_members = NULL;
    }

    zend_hash_clean(&src->default_properties);
#endif
    zend_hash_clean(&src->constants_table);

#ifdef ZEND_ENGINE_2_4
#if 0
    /* XXX function freeing seems to be still a fail even in 5.4 as well, so let it down for now */
    my_free_hashtable(&src->function_table, APC_FREE_HASHTABLE_FUNCS TSRMLS_CC);

    my_free_hashtable(&src->properties_info, APC_FREE_HASHTABLE_PROPS TSRMLS_CC);
    my_free_hashtable(&src->constants_table, APC_FREE_HASHTABLE_STATIC_PROPS TSRMLS_CC);
    src->trait_aliases = NULL; /* XXX free all the traits stuff */
#endif
#endif

    /* TODO: more cleanup */
}
/* }}} */

/* {{{ apc_file_halt_offset */
long apc_file_halt_offset(const char *filename TSRMLS_DC)
{
    zend_constant *c;
    char *name;
    int len;
    char haltoff[] = "__COMPILER_HALT_OFFSET__";
    long value = -1;

    zend_mangle_property_name(&name, &len, haltoff, sizeof(haltoff) - 1, filename, strlen(filename), 0);
    
    if (zend_hash_find(EG(zend_constants), name, len+1, (void **) &c) == SUCCESS) {
        value = Z_LVAL(c->value);
    }
    
    pefree(name, 0);

    return value;
}
/* }}} */

/* {{{ apc_do_halt_compiler_register */
void apc_do_halt_compiler_register(const char *filename, long halt_offset TSRMLS_DC)
{
    char *name;
    char haltoff[] = "__COMPILER_HALT_OFFSET__";
    int len;
   
    if(halt_offset > 0) {
        
        zend_mangle_property_name(&name, &len, haltoff, sizeof(haltoff) - 1, 
                                    filename, strlen(filename), 0);
        
        zend_register_long_constant(name, len+1, halt_offset, CONST_CS, 0 TSRMLS_CC);

        pefree(name, 0);
    }
}
/* }}} */

/* {{{ my_fixup_function */
static void my_fixup_function(Bucket *p, zend_class_entry *src, zend_class_entry *dst)
{
    zend_function* zf = p->pData;

    #define SET_IF_SAME_NAME(member) \
    do { \
        if(src->member && !strcmp(zf->common.function_name, src->member->common.function_name)) { \
            dst->member = zf; \
        } \
    } \
    while(0)

    if(zf->common.scope == src)
    {

        /* Fixing up the default functions for objects here since
         * we need to compare with the newly allocated functions
         *
         * caveat: a sub-class method can have the same name as the
         * parent's constructor and create problems.
         */

        if(zf->common.fn_flags & ZEND_ACC_CTOR) dst->constructor = zf;
        else if(zf->common.fn_flags & ZEND_ACC_DTOR) dst->destructor = zf;
        else if(zf->common.fn_flags & ZEND_ACC_CLONE) dst->clone = zf;
        else
        {
            SET_IF_SAME_NAME(__get);
            SET_IF_SAME_NAME(__set);
            SET_IF_SAME_NAME(__unset);
            SET_IF_SAME_NAME(__isset);
            SET_IF_SAME_NAME(__call);
#ifdef ZEND_ENGINE_2_2
            SET_IF_SAME_NAME(__tostring);
#endif
#ifdef ZEND_ENGINE_2_3
            SET_IF_SAME_NAME(__callstatic);
#endif
        }
        zf->common.scope = dst;
    }
    else
    {
        /* no other function should reach here */
        assert(0);
    }

    #undef SET_IF_SAME_NAME
}
/* }}} */

#ifdef ZEND_ENGINE_2_2
/* {{{ my_fixup_property_info */
static void my_fixup_property_info(Bucket *p, zend_class_entry *src, zend_class_entry *dst)
{
    zend_property_info* property_info = (zend_property_info*)p->pData;

    if(property_info->ce == src)
    {
        property_info->ce = dst;
    }
    else
    {
        assert(0); /* should never happen */
    }
}
/* }}} */
#endif

/* {{{ my_fixup_hashtable */
static void my_fixup_hashtable(HashTable *ht, ht_fixup_fun_t fixup, zend_class_entry *src, zend_class_entry *dst)
{
    Bucket *p;
    uint i;

    for (i = 0; i < ht->nTableSize; i++) {
        if(!ht->arBuckets) break;
        p = ht->arBuckets[i];
        while (p != NULL) {
            fixup(p, src, dst);
            p = p->pNext;
        }
    }
}
/* }}} */

/* {{{ my_check_copy_function */
static int my_check_copy_function(Bucket* p, va_list args)
{
    zend_class_entry* src = va_arg(args, zend_class_entry*);
    zend_function* zf = (zend_function*)p->pData;

    return (zf->common.scope == src);
}
/* }}} */

#ifndef ZEND_ENGINE_2_4
/* {{{ my_check_copy_default_property */
static int my_check_copy_default_property(Bucket* p, va_list args)
{
    zend_class_entry* src = va_arg(args, zend_class_entry*);
    zend_class_entry* parent = src->parent;
    zval ** child_prop = (zval**)p->pData;
    zval ** parent_prop = NULL;

    if (parent &&
        zend_hash_quick_find(&parent->default_properties, p->arKey, 
            p->nKeyLength, p->h, (void **) &parent_prop)==SUCCESS) {

        if((parent_prop && child_prop) && (*parent_prop) == (*child_prop))
        {
            return 0;
        }
    }

    /* possibly not in the parent */
    return 1;
}
/* }}} */
#endif

/* {{{ my_check_copy_property_info */
static int my_check_copy_property_info(Bucket* p, va_list args)
{
    zend_class_entry* src = va_arg(args, zend_class_entry*);
    zend_class_entry* parent = src->parent;
    zend_property_info* child_info = (zend_property_info*)p->pData;
    zend_property_info* parent_info = NULL;

#ifdef ZEND_ENGINE_2_2
    /* so much easier */
    return (child_info->ce == src);
#endif

    if (parent &&
        zend_hash_quick_find(&parent->properties_info, p->arKey, p->nKeyLength,
            p->h, (void **) &parent_info)==SUCCESS) {
        if(parent_info->flags & ZEND_ACC_PRIVATE)
        {
            return 1;
        }
        if((parent_info->flags & ZEND_ACC_PPP_MASK) !=
            (child_info->flags & ZEND_ACC_PPP_MASK))
        {
            /* TODO: figure out whether ACC_CHANGED is more appropriate
             * here */
            return 1;
        }
        return 0;
    }

    /* property doesn't exist in parent, copy into cached child */
    return 1;
}
/* }}} */

#ifndef ZEND_ENGINE_2_4
/* {{{ my_check_copy_static_member */
static int my_check_copy_static_member(Bucket* p, va_list args)
{
    zend_class_entry* src = va_arg(args, zend_class_entry*);
    HashTable * ht = va_arg(args, HashTable*);
    zend_class_entry* parent = src->parent;
    HashTable * parent_ht = NULL;
    char * member_name;
    char * class_name = NULL;

    zend_property_info *parent_info = NULL;
    zend_property_info *child_info = NULL;
    zval ** parent_prop = NULL;
    zval ** child_prop = (zval**)(p->pData);

    if(!parent) {
        return 1;
    }

    /* these do not need free'ing */
#ifdef ZEND_ENGINE_2_2
    zend_unmangle_property_name(p->arKey, p->nKeyLength-1, &class_name, &member_name);
#else
    zend_unmangle_property_name(p->arKey, &class_name, &member_name);
#endif

    /* please refer do_inherit_property_access_check in zend_compile.c
     * to understand why we lookup in properties_info.
     */
    if((zend_hash_find(&parent->properties_info, member_name,
                        strlen(member_name)+1, (void**)&parent_info) == SUCCESS)
        &&
        (zend_hash_find(&src->properties_info, member_name,
                        strlen(member_name)+1, (void**)&child_info) == SUCCESS))
    {
        if(ht == &(src->default_static_members))
        {
            parent_ht = &parent->default_static_members;
        }
        else
        {
            parent_ht = parent->static_members;
        }

        if(zend_hash_quick_find(parent_ht, p->arKey,
                       p->nKeyLength, p->h, (void**)&parent_prop) == SUCCESS)
        {
            /* they point to the same zval */
            if(*parent_prop == *child_prop)
            {
                return 0;
            }
        }
    }

    return 1;
}
/* }}} */
#endif

/* {{{ my_check_copy_constant */
static int my_check_copy_constant(Bucket* p, va_list args)
{
    zend_class_entry* src = va_arg(args, zend_class_entry*);
    zend_class_entry* parent = src->parent;
    zval ** child_const = (zval**)p->pData;
    zval ** parent_const = NULL;

    if (parent &&
        zend_hash_quick_find(&parent->constants_table, p->arKey, 
            p->nKeyLength, p->h, (void **) &parent_const)==SUCCESS) {

        if((parent_const && child_const) && (*parent_const) == (*child_const))
        {
            return 0;
        }
    }

    /* possibly not in the parent */
    return 1;
}
/* }}} */

/* {{{ apc_register_optimizer(apc_optimize_function_t optimizer)
 *      register a optimizer callback function, returns the previous callback
 */
apc_optimize_function_t apc_register_optimizer(apc_optimize_function_t optimizer TSRMLS_DC) {
    apc_optimize_function_t old_optimizer = APCG(apc_optimize_function);
    APCG(apc_optimize_function) = optimizer;
    return old_optimizer;
}
/* }}} */

#ifdef ZEND_ENGINE_2_4

#define APC_COPY_TRAIT_METHOD(dst, src) \
    CHECK(dst = \
         (zend_trait_method_reference *)apc_pool_alloc(ctxt->pool, sizeof(zend_trait_method_reference))); \
    memcpy(dst, src, sizeof(zend_trait_method_reference)); \
\
    if (src->method_name) { \
        CHECK((dst->method_name = apc_pstrdup(src->method_name, ctxt->pool TSRMLS_CC))); \
        dst->mname_len = src->mname_len; \
    } \
 \
    if (src->class_name) { \
        CHECK((dst->class_name = apc_pstrdup(src->class_name, ctxt->pool TSRMLS_CC))); \
        dst->cname_len = src->cname_len; \
    } \
    if (src->ce) { \
        dst->ce = my_copy_class_entry(NULL, src->ce, ctxt TSRMLS_CC); \
    }

#define APC_COPY_TRAIT_METHOD_FOR_EXEC(dst, src) \
    dst = (zend_trait_method_reference *) apc_pool_alloc(ctxt->pool, sizeof(zend_trait_method_reference)); \
    memcpy(dst, src, sizeof(zend_trait_method_reference)); \
    if (src->method_name) { \
        CHECK((dst->method_name = apc_pstrdup(src->method_name, ctxt->pool TSRMLS_CC))); \
    } \
\
    if (src->class_name) { \
        CHECK((dst->class_name = apc_pstrdup(src->class_name, ctxt->pool TSRMLS_CC))); \
    } \
    if (src->ce) { \
        dst->ce = apc_copy_class_entry_for_execution(src->ce, ctxt TSRMLS_CC); \
    }

/* {{{ apc_copy_trait_alias */
zend_trait_alias* apc_copy_trait_alias(zend_trait_alias *dst, zend_trait_alias *src, apc_context_t *ctxt TSRMLS_DC)
{
    if (!dst) {
        CHECK(dst = (zend_trait_alias *) apc_pool_alloc(ctxt->pool, sizeof(zend_trait_alias)));
    }
    memcpy(dst, src, sizeof(zend_trait_alias));

    if (src->alias) {
        CHECK((dst->alias = apc_pstrdup(src->alias, ctxt->pool TSRMLS_CC)));
        dst->alias_len = src->alias_len;
    }

    if (src->function) {
        CHECK(dst->function = my_copy_function(NULL, src->function, ctxt TSRMLS_CC));
    }

    APC_COPY_TRAIT_METHOD(dst->trait_method, src->trait_method);

    return dst;
}
/* }}} */

/* {{{ apc_copy_trait_alias_for_execution */
zend_trait_alias* apc_copy_trait_alias_for_execution(zend_trait_alias *src, apc_context_t *ctxt TSRMLS_DC)
{
    zend_trait_alias *dst = (zend_trait_alias *) apc_pool_alloc(ctxt->pool, sizeof(zend_trait_alias));

    memcpy(dst, src, sizeof(zend_trait_alias));

    if (src->alias) {
        CHECK((dst->alias = apc_pstrdup(src->alias, ctxt->pool TSRMLS_CC)));
    }

    /* XXX function is not handled here, check if it's right */

    APC_COPY_TRAIT_METHOD_FOR_EXEC(dst->trait_method, src->trait_method);

    return dst;
}
/* }}} */

/* {{{ apc_copy_trait_precedence */
zend_trait_precedence* apc_copy_trait_precedence(zend_trait_precedence *dst, zend_trait_precedence *src, apc_context_t *ctxt TSRMLS_DC)
{
    if (!dst) {
        CHECK(dst = (zend_trait_precedence *) apc_pool_alloc(ctxt->pool, sizeof(zend_trait_precedence)));
    }
    memcpy(dst, src, sizeof(zend_trait_precedence));

    if (src->function) {
        CHECK(dst->function = my_copy_function(NULL, src->function, ctxt TSRMLS_CC));
    } 

    if (src->exclude_from_classes && *src->exclude_from_classes) {
        int i = 0, num_classes = 0;

        while (src->exclude_from_classes[num_classes]) { num_classes++; }

        CHECK(dst->exclude_from_classes =
            (zend_class_entry **) apc_pool_alloc(ctxt->pool, sizeof(zend_class_entry *)*(num_classes+1)));

        while (src->exclude_from_classes[i] && i < num_classes) {
            char *name = (char *) src->exclude_from_classes[i];

            dst->exclude_from_classes[i] = (zend_class_entry *) apc_pstrdup(name, ctxt->pool TSRMLS_CC);
            i++;
        }
        dst->exclude_from_classes[i] = NULL;
    }

    APC_COPY_TRAIT_METHOD(dst->trait_method, src->trait_method);

    return dst;
}
/* }}} */

/* {{{ apc_copy_trait_precedence_for_execution */
zend_trait_precedence* apc_copy_trait_precedence_for_execution(zend_trait_precedence *src, apc_context_t *ctxt TSRMLS_DC)
{
    zend_trait_precedence *dst = (zend_trait_precedence *) apc_pool_alloc(ctxt->pool, sizeof(zend_trait_precedence));

    memcpy(dst, src, sizeof(zend_trait_precedence));

    if (src->exclude_from_classes && *src->exclude_from_classes) {
        int i = 0, num_classes = 0;

        while (src->exclude_from_classes[num_classes]) { num_classes++; }

        CHECK(dst->exclude_from_classes = 
            (zend_class_entry **) apc_pool_alloc(ctxt->pool, sizeof(zend_class_entry *)*(num_classes+1)));

        while (src->exclude_from_classes[i] && i < num_classes) {
            char *name = (char *) src->exclude_from_classes[i];

            dst->exclude_from_classes[i] = (zend_class_entry *) apc_pstrdup(name, ctxt->pool TSRMLS_CC);
            i++;
        }
        dst->exclude_from_classes[i] = NULL;
    }

    /* XXX function is not handled here, check if it's right */

    APC_COPY_TRAIT_METHOD(dst->trait_method, src->trait_method);

    return dst;
}
/* }}} */
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim>600: expandtab sw=4 ts=4 sts=4 fdm=marker
 * vim<600: expandtab sw=4 ts=4 sts=4
 */
