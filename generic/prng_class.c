#include "tomcryptInt.h"
#include <tclTomMath.h>	/* mp_int and TclBN_mp_* stubs */

#ifndef TCL_OO_METHOD_PUBLIC
# define TCL_OO_METHOD_PUBLIC 1
#endif

struct prng_md {
	prng_state					prng;
	int							initialized;
	int							desc_idx;
	struct ltc_prng_descriptor*	desc;
};

static void delete_prng_state(ClientData cdata) //<<<
{
	struct prng_md*	md = (struct prng_md*)cdata;

	if (md->initialized)
		md->desc->done(&md->prng);

	ckfree(md);
	md = NULL;
}

//>>>
static int clone_prng_state(Tcl_Interp* interp, void* cdata, void** new_cdata) //<<<
{
	(void)interp;
	int						code = TCL_OK;
	struct prng_md*			md = (struct prng_md*)cdata;
	struct prng_md*			new_md = NULL;
	uint8_t*				export = NULL;

	export = ckalloc(md->desc->export_size);
	unsigned long	export_len = md->desc->export_size;
	if (CRYPT_OK != md->desc->pexport(export, &export_len, &md->prng)) {
		code = TCL_ERROR;
		goto finally;
	}

	new_md = ckalloc(sizeof(*new_md));
	*new_md = (struct prng_md){
		.desc_idx	= md->desc_idx,
		.desc		= md->desc,
	};
	if (
			CRYPT_OK != new_md->desc->start(&new_md->prng) ||
			CRYPT_OK != new_md->desc->pimport(export, export_len, &new_md->prng)
	) {
		code = TCL_ERROR;
		goto finally;
	}

	*new_cdata = new_md;
	new_md = NULL;	// Hand ownership to the new object metadata

finally:
	if (export) {
		ckfree(export);
		export = NULL;
	}

	if (new_md) {
		delete_prng_state(new_md);
		new_md = NULL;
	}

	return code;
}

//>>>

static Tcl_ObjectMetadataType prng_metadata = {
	.version	= TCL_OO_METADATA_VERSION_CURRENT,
	.name		= "prng_state",
	.deleteProc	= delete_prng_state,
	.cloneProc	= clone_prng_state
};


static int ctor(ClientData cdata, Tcl_Interp* interp, Tcl_ObjectContext context, int objc, Tcl_Obj*const objv[]) //<<<
{
	(void)cdata;
	int					code = TCL_OK;
	Tcl_Object			object = Tcl_ObjectContextObject(context);
	struct prng_md*		md = NULL;
	int					err;

	const int	A_cmd		= Tcl_ObjectContextSkippedArgs(context)-1;
	const int	A_TYPE		= A_cmd+1;
	const int	A_args		= A_cmd+2;
	const int	A_ENTROPY	= A_cmd+2;
	const int	A_objc		= A_cmd+3;
	CHECK_RANGE_ARGS_LABEL(finally, code, "type ?entropy?");

	Tcl_Size	type_len;
	const char*	type = Tcl_GetStringFromObj(objv[A_TYPE], &type_len);
	if (type_len == 0) {
		// When a blank string is given for type, it triggers the "implementation recommeded" selection
		type = "fortuna";
		type_len = strlen(type);
	}

	md = ckalloc(sizeof(*md));
	*md = (struct prng_md){
		.desc_idx	= find_prng(type),
	};
	if (md->desc_idx == -1) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "UNREGISTERED", "PRNG", Tcl_GetString(objv[A_TYPE]), NULL);
		THROW_PRINTF_LABEL(finally, code, "PRNG implementation \"%s\" not registered", Tcl_GetString(objv[A_TYPE]));
	}
	md->desc = &prng_descriptor[md->desc_idx];

	if (CRYPT_OK != (err = md->desc->start(&md->prng))) {
		THROW_PRINTF_LABEL(finally, code, "PRNG implementation %s failed to start: %s",
				Tcl_GetString(objv[A_TYPE]),
				error_to_string(err));
	}
	md->initialized = 1;

	if (A_ENTROPY < objc) {
		Tcl_Size		entropy_len = 0;
		const uint8_t*	entropy = Tcl_GetBytesFromObj(interp, objv[A_ENTROPY], &entropy_len);
		if (entropy == NULL) { code = TCL_ERROR; goto finally; }

		if (entropy_len < 8) {
			Tcl_SetErrorCode(interp, "TOMCRYPT", "VALUE", NULL);
			THROW_ERROR_LABEL(finally, code, "insufficient entropy supplied");
		}

		if (entropy_len == md->desc->export_size) {
			if (CRYPT_OK != (err = md->desc->pimport(entropy, entropy_len, &md->prng))) {
				THROW_PRINTF_LABEL(finally, code, "PRNG implementation %s failed to import entropy: %s",
						Tcl_GetString(objv[A_TYPE]),
						error_to_string(err));
			}
		} else {
			if (CRYPT_OK != (err = md->desc->add_entropy(entropy, entropy_len, &md->prng))) {
				THROW_PRINTF_LABEL(finally, code, "PRNG implementation %s failed to add entropy: %s",
						Tcl_GetString(objv[A_TYPE]),
						error_to_string(err));
			}
		}
	} else {
		if (CRYPT_OK != (err = rng_make_prng(256, md->desc_idx, &md->prng, NULL))) {
			THROW_PRINTF_LABEL(finally, code, "PRNG implementation %s failed to seed: %s",
					Tcl_GetString(objv[A_TYPE]),
					error_to_string(err));
		}
	}

	if (CRYPT_OK != (err = md->desc->ready(&md->prng))) {
		THROW_PRINTF_LABEL(finally, code, "PRNG implementation %s failed to ready: %s",
				Tcl_GetString(objv[A_TYPE]),
				error_to_string(err));
	}

	Tcl_ObjectSetMetadata(object, &prng_metadata,	md);
	md = NULL;	// Hand ownership to the object metadata

finally:
	if (md) {
		delete_prng_state(md);
		md = NULL;
	}
	return code;
}

//>>>
static int method_bytes(ClientData cdata, Tcl_Interp* interp, Tcl_ObjectContext context, int objc, Tcl_Obj*const objv[]) //<<<
{
	int						code = TCL_OK;
	struct interp_cx*		l = (struct interp_cx*)cdata;
	Tcl_Object				object = Tcl_ObjectContextObject(context);
	struct prng_md*			md = Tcl_ObjectGetMetadata(object, &prng_metadata);
	Tcl_Obj*				res = NULL;

	const int	A_cmd		= Tcl_ObjectContextSkippedArgs(context)-1;
	const int	A_BYTES		= A_cmd+1;
	const int	A_objc		= A_cmd+2;
	CHECK_ARGS_LABEL(finally, code, "count");

	int	count = 0;
	TEST_OK_LABEL(finally, code, Tcl_GetIntFromObj(interp, objv[A_BYTES], &count));

	if (count < 0) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "VALUE", NULL);
		THROW_ERROR_LABEL(finally, code, "count cannot be negative");
	}

	if (count == 0) {
		Tcl_SetObjResult(interp, l->lit[L_NOBYTES]);
		goto finally;
	}

	uint32_t			buflen = count;
	replace_tclobj(&res, Tcl_NewByteArrayObj(NULL, buflen));
	uint8_t*			buf = Tcl_GetBytesFromObj(interp, res, NULL);
	if (buf == NULL) { code = TCL_ERROR; goto finally; }
	const unsigned long	got = md->desc->read(buf, buflen, &md->prng);
	if (got != buflen) {
		// buf = Tcl_SetByteArrayLength(buf, got);
		Tcl_SetErrorCode(interp, "TOMCRYPT", "PRNG", "READ", NULL);
		THROW_PRINTF_LABEL(finally, code, "PRNG implementation %s failed to read %d bytes",
				md->desc->name, count);
	}

	Tcl_SetObjResult(interp, res);

finally:
	replace_tclobj(&res, NULL);
	return code;
}

//>>>
static int method_add_entropy(ClientData cdata, Tcl_Interp* interp, Tcl_ObjectContext context, int objc, Tcl_Obj*const objv[]) //<<<
{
	(void)cdata;
	int						code = TCL_OK;
	Tcl_Object				object = Tcl_ObjectContextObject(context);
	struct prng_md*			md = Tcl_ObjectGetMetadata(object, &prng_metadata);
	int						err;

	const int	A_cmd		= Tcl_ObjectContextSkippedArgs(context)-1;
	const int	A_ENTROPY	= A_cmd+1;
	const int	A_objc		= A_cmd+2;
	CHECK_ARGS_LABEL(finally, code, "entropy");

	Tcl_Size		entropy_len = 0;
	const uint8_t*	entropy = Tcl_GetBytesFromObj(interp, objv[A_ENTROPY], &entropy_len);
	if (entropy == NULL) { code = TCL_ERROR; goto finally; }

	if (entropy_len == 0) goto finally;

	if (CRYPT_OK != (err = md->desc->add_entropy(entropy, entropy_len, &md->prng))) {
		THROW_PRINTF_LABEL(finally, code, "PRNG implementation %s failed to add entropy: %s",
				md->desc->name, error_to_string(err));
	}

finally:
	return code;
}

//>>>
static int method_integer(ClientData cdata, Tcl_Interp* interp, Tcl_ObjectContext context, int objc, Tcl_Obj*const objv[]) //<<<
{
	(void)cdata;
	int						code = TCL_OK;
	Tcl_Object				object = Tcl_ObjectContextObject(context);
	struct prng_md*			md = Tcl_ObjectGetMetadata(object, &prng_metadata);
	Tcl_Obj*				res = NULL;
	Tcl_Obj*				tmp = NULL;

	const int	A_cmd		= Tcl_ObjectContextSkippedArgs(context)-1;
	const int	A_LOWER		= A_cmd+1;
	const int	A_UPPER		= A_cmd+2;
	const int	A_objc		= A_cmd+3;
	CHECK_ARGS_LABEL(finally, code, "lower upper");

	// Classify each input as an integer (fits in Tcl_WideInt) or a bignum.
	// Tcl_GetNumberFromObj is the native way to do this on Tcl 9, but it's
	// private in Tcl 8.6, so we fall back to trying Tcl_GetWideIntFromObj
	// and then Tcl_GetBignumFromObj there.
	int			lower_is_big = 0, upper_is_big = 0;
	Tcl_WideInt	lower_wide = 0, upper_wide = 0;
#if TCL_MAJOR_VERSION >= 9
	{
		void	*lower_info = NULL, *upper_info = NULL;
		int		lower_type, upper_type;
		TEST_OK_LABEL(finally, code, Tcl_GetNumberFromObj(interp, objv[A_LOWER], &lower_info, &lower_type));
		TEST_OK_LABEL(finally, code, Tcl_GetNumberFromObj(interp, objv[A_UPPER], &upper_info, &upper_type));
		if (lower_type != TCL_NUMBER_INT && lower_type != TCL_NUMBER_BIG) {
			Tcl_SetErrorCode(interp, "TCL", "VALUE", "NUMBER", NULL);
			THROW_PRINTF_LABEL(finally, code, "expected integer but got \"%s\"", Tcl_GetString(objv[A_LOWER]));
		}
		if (upper_type != TCL_NUMBER_INT && upper_type != TCL_NUMBER_BIG) {
			Tcl_SetErrorCode(interp, "TCL", "VALUE", "NUMBER", NULL);
			THROW_PRINTF_LABEL(finally, code, "expected integer but got \"%s\"", Tcl_GetString(objv[A_UPPER]));
		}
		lower_is_big = lower_type == TCL_NUMBER_BIG;
		upper_is_big = upper_type == TCL_NUMBER_BIG;
		if (!lower_is_big) lower_wide = *(Tcl_WideInt*)lower_info;
		if (!upper_is_big) upper_wide = *(Tcl_WideInt*)upper_info;
	}
#else
	// Tcl 8.6: Tcl_GetNumberFromObj is private.  Probe with Tcl_GetWideIntFromObj
	// then fall back to Tcl_GetBignumFromObj to distinguish int, big, and
	// not-a-number.
	lower_is_big = Tcl_GetWideIntFromObj(NULL, objv[A_LOWER], &lower_wide) != TCL_OK;
	upper_is_big = Tcl_GetWideIntFromObj(NULL, objv[A_UPPER], &upper_wide) != TCL_OK;
	if (lower_is_big) {
		mp_int probe = {0};
		if (TCL_OK != Tcl_GetBignumFromObj(NULL, objv[A_LOWER], &probe)) {
			Tcl_SetErrorCode(interp, "TCL", "VALUE", "NUMBER", NULL);
			THROW_PRINTF_LABEL(finally, code, "expected integer but got \"%s\"", Tcl_GetString(objv[A_LOWER]));
		}
		mp_clear(&probe);
	}
	if (upper_is_big) {
		mp_int probe = {0};
		if (TCL_OK != Tcl_GetBignumFromObj(NULL, objv[A_UPPER], &probe)) {
			Tcl_SetErrorCode(interp, "TCL", "VALUE", "NUMBER", NULL);
			THROW_PRINTF_LABEL(finally, code, "expected integer but got \"%s\"", Tcl_GetString(objv[A_UPPER]));
		}
		mp_clear(&probe);
	}
#endif

	if (!lower_is_big && !upper_is_big) {
		const Tcl_WideInt		lower_val = lower_wide;
		const Tcl_WideInt		upper_val = upper_wide;

		if (lower_val > upper_val) {
			Tcl_SetErrorCode(interp, "TOMCRYPT", "VALUE", NULL);
			THROW_ERROR_LABEL(finally, code, "lower must be less than or equal to upper");
		}

		const Tcl_WideUInt		range = upper_val - lower_val;

		if (range == 0) {
			// Shrug.  I guess it's still random and uniform in given the
			// range.  Sure, here's your random constant
			Tcl_SetObjResult(interp, objv[A_LOWER]);
			goto finally;
		}

		const uint32_t	range_bitlen = (uint32_t)log2(range);
		const uint32_t	range_bytelen = (range_bitlen+7)/8;
		Tcl_WideUInt	range_mask = (UINT64_C(1)<<(range_bitlen+1))-1;
		// range_bytelen is in [1, 8] (log2 of a Tcl_WideUInt range).  Use a
		// fixed-size buffer and memcpy to compose the value, so we don't
		// read past the buffer end (which would trample the stack canary
		// when range_bytelen < sizeof(Tcl_WideUInt)) and so the endianness
		// of the reinterpretation is explicit and portable (little-endian).
		uint8_t			buf[sizeof(Tcl_WideUInt)] = {0};

		// To enforce uniform (unbiased) distribution, we need to keep rolling
		// until a masked value is in range, worst case should be a 50% chance per roll
		for (int i=0; i<100; i++) {
			const unsigned long got = md->desc->read(buf, range_bytelen, &md->prng);
			if (got != range_bytelen) {
				Tcl_SetErrorCode(interp, "TOMCRYPT", "PRNG", "READ", NULL);
				THROW_PRINTF_LABEL(finally, code, "PRNG implementation %s failed to read %d bytes",
						md->desc->name, range_bytelen);
			}
			Tcl_WideUInt value = 0;
			for (uint32_t j = 0; j < range_bytelen; j++) {
				value |= (Tcl_WideUInt)buf[j] << (8 * j);
			}
			value &= range_mask;
			if (value <= range) {
				Tcl_SetObjResult(interp, Tcl_NewWideIntObj(lower_val + value));
				goto finally;
			}
			//fprintf(stderr, "%3d: rolled bytes: %ld, range: %" PRIu64 ", value: %" PRIu64 ", range_bitlen: %d, range_bytelen: %d, range_mask: 0x%016" PRIX64 "\n", i, got, range, value, range_bitlen, range_bytelen, range_mask);
		}

		// Circuit breaker - if we haven't rolled a value in range after 100
		// tries (at most a 1/2**100 chance), then the prng is almost certainly faulty
		THROW_PRINTF_LABEL(finally, code, "PRNG implementation %s failed to generate a value in range after 100 tries", md->desc->name);
	} else {
		// At least one of the values is a bignum.  All mp_int ops here go
		// through TclBN stubs (see <tclTomMath.h>), so the digit arrays are
		// allocated and freed by Tcl's own libtommath.
		int			rc;
		mp_int		lower_bigval = {0};
		mp_int		upper_bigval = {0};
		mp_int		range_bigval = {0};
		mp_int		value_bigval = {0};
		int			mp_inited = 0;	// bits: 0x1=lower, 0x2=upper, 0x4=range, 0x8=value
		uint32_t	range_bitlen_bigval;
		uint32_t	range_bytelen_bigval;
		uint32_t	range_remain_bigval;

		// Avoid dynamic allocation for small(ish) ranges
		uint8_t		buf_bigval_static[BUF_BIGVAL_STATIC_BYTES];
		uint8_t*	buf_bigval = buf_bigval_static;
		char		hexrep_static[2*BUF_BIGVAL_STATIC_BYTES+1];
		char*		hexrep = hexrep_static;

		if (MP_OKAY != (rc = mp_init_multi(&range_bigval, &value_bigval, NULL)))		goto mp_err;
		mp_inited |= 0x4 | 0x8;

		TEST_OK_LABEL(mp_finally, code, Tcl_GetBignumFromObj(interp, objv[A_LOWER], &lower_bigval));
		mp_inited |= 0x1;
		TEST_OK_LABEL(mp_finally, code, Tcl_GetBignumFromObj(interp, objv[A_UPPER], &upper_bigval));
		mp_inited |= 0x2;

		switch (mp_cmp_mag(&lower_bigval, &upper_bigval)) {
			case MP_LT: break;
			case MP_GT:
				Tcl_SetErrorCode(interp, "TOMCRYPT", "VALUE", NULL);
				THROW_ERROR_LABEL(mp_finally, code, "lower must be less than or equal to upper");
			case MP_EQ:
				// Shrug.  I guess it's still random and uniform in given the
				// range.  Sure, here's your random constant
				Tcl_SetObjResult(interp, objv[A_LOWER]);
				goto mp_finally;
		}
		if (MP_OKAY != (rc = mp_sub(&upper_bigval, &lower_bigval, &range_bigval)))		goto mp_err;
		range_bitlen_bigval  = mp_count_bits(&range_bigval);
		range_bytelen_bigval = (range_bitlen_bigval+7)/8;
		range_remain_bigval  = range_bitlen_bigval % 8;
		uint8_t	topbyte_mask = range_remain_bigval ? (UINT64_C(1)<<range_remain_bigval)-1 : 0xff;

		if (range_bytelen_bigval > BUF_BIGVAL_STATIC_BYTES) {
			buf_bigval	= (uint8_t*)ckalloc(range_bytelen_bigval);
			hexrep		= ckalloc(2*range_bytelen_bigval+1);
		}

		// To enforce uniform (unbiased) distribution, we need to keep rolling
		// until a masked value is in range, worst case should be a 50% chance per roll
		for (int i=0; i<100; i++) {
			const unsigned long got = md->desc->read(buf_bigval, range_bytelen_bigval, &md->prng);
			if (got != range_bytelen_bigval) {
				Tcl_SetErrorCode(interp, "TOMCRYPT", "PRNG", "READ", NULL);
				THROW_PRINTF_LABEL(mp_finally, code, "PRNG implementation %s failed to read %d bytes",
						md->desc->name, range_bytelen_bigval);
			}
			buf_bigval[0] &= topbyte_mask;

			// mp_from_ubin is not in the TclBN stubs subset, so we build a hex string
			// rep of the random bytes and parse it with mp_read_radix instead.
			for (uint32_t j=0; j<range_bytelen_bigval; j++) {
				static const char hexdigits[] = "0123456789abcdef";
				hexrep[2*j  ] = hexdigits[buf_bigval[j] >> 4];
				hexrep[2*j+1] = hexdigits[buf_bigval[j] & 0xf];
			}
			hexrep[2*range_bytelen_bigval] = '\0';

			if (MP_OKAY != (rc = mp_read_radix(&value_bigval, hexrep, 16)))				goto mp_err;
			if (MP_GT == mp_cmp_mag(&value_bigval, &range_bigval))						continue;
			if (MP_OKAY != (rc = mp_add(&lower_bigval, &value_bigval, &value_bigval)))	goto mp_err;
			// With TclBN stubs, mp_init/mp_clear use Tcl's allocator, so
			// Tcl_NewBignumObj can safely take ownership of value_bigval.dp.
			Tcl_SetObjResult(interp, Tcl_NewBignumObj(&value_bigval));
			mp_inited &= ~0x8;	// Tcl_NewBignumObj hollowed out value_bigval
			goto mp_finally;
		}

		// Circuit breaker - if we haven't rolled a value in range after 100
		// tries (at most a 1/2**100 chance), then the prng is almost certainly faulty
		THROW_PRINTF_LABEL(mp_finally, code, "PRNG implementation %s failed to generate a value in range after 100 tries", md->desc->name);

mp_finally:
		if (mp_inited & 0x1) mp_clear(&lower_bigval);
		if (mp_inited & 0x2) mp_clear(&upper_bigval);
		if (mp_inited & 0x4) mp_clear(&range_bigval);
		if (mp_inited & 0x8) mp_clear(&value_bigval);
		if (buf_bigval != buf_bigval_static) {
			ckfree(buf_bigval);
			SUPPRESS_DEADSTORE buf_bigval = buf_bigval_static;
		}
		if (hexrep != hexrep_static) {
			ckfree(hexrep);
			SUPPRESS_DEADSTORE hexrep = hexrep_static;
		}
		goto finally;

mp_err:
		THROW_PRINTF_LABEL(mp_finally, code, "libtommath operation failed: rc=%d", rc);
		goto mp_finally;
	}

finally:
	replace_tclobj(&tmp, NULL);
	replace_tclobj(&res, NULL);
	return code;
}

//>>>
static int method_double(ClientData cdata, Tcl_Interp* interp, Tcl_ObjectContext context, int objc, Tcl_Obj*const objv[]) //<<<
{
	(void)cdata;
	int						code = TCL_OK;
	Tcl_Object				object = Tcl_ObjectContextObject(context);
	struct prng_md*			md = Tcl_ObjectGetMetadata(object, &prng_metadata);

	const int	A_cmd		= Tcl_ObjectContextSkippedArgs(context)-1;
	const int	A_objc		= A_cmd+1;
	CHECK_ARGS_LABEL(finally, code, "");

	uint64_t	value;
	const unsigned long got = md->desc->read((uint8_t*)&value, sizeof(value), &md->prng);
	if (got != sizeof(value)) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "PRNG", "READ", NULL);
		THROW_PRINTF_LABEL(finally, code, "PRNG implementation %s failed to read %zd bytes",
				md->desc->name, sizeof(value));
	}

	// To ensure uniform distribution and equal resolution across the range [0, 1),
	// we mask down to the 53 bits of the mantissa of a double (with the hidden bit)
	// https://stackoverflow.com/a/43553449/17366742
	value &= (UINT64_C(1)<<53)-1;
	Tcl_SetObjResult(interp, Tcl_NewDoubleObj((double)value / (double)(UINT64_C(1)<<53)));

finally:
	return code;
}

//>>>
static int method_export(ClientData cdata, Tcl_Interp* interp, Tcl_ObjectContext context, int objc, Tcl_Obj*const objv[]) //<<<
{
	int						code = TCL_OK;
	struct interp_cx*		l = (struct interp_cx*)cdata;
	Tcl_Object				object = Tcl_ObjectContextObject(context);
	struct prng_md*			md = Tcl_ObjectGetMetadata(object, &prng_metadata);
	int						err;
	Tcl_Obj*				res = NULL;

	const int	A_cmd		= Tcl_ObjectContextSkippedArgs(context)-1;
	const int	A_objc		= A_cmd+1;
	CHECK_ARGS_LABEL(finally, code, "");

	if (md->desc->export_size == 0) {
		// Throw an error instead?
		Tcl_SetObjResult(interp, l->lit[L_NOBYTES]);
		goto finally;
	}

	int			export_size = md->desc->export_size;
	if (export_size < 0)
		THROW_PRINTF_LABEL(finally, code, "PRNG implementation %s has invalid export size %d", md->desc->name, export_size);
	replace_tclobj(&res, Tcl_NewByteArrayObj(NULL, export_size));
	uint8_t*	export = Tcl_GetBytesFromObj(interp, res, NULL);
	if (export == NULL) { code = TCL_ERROR; goto finally; }
	long unsigned int	export_size_ul = export_size;
	if (CRYPT_OK != (err = md->desc->pexport(export, &export_size_ul, &md->prng))) {
		THROW_PRINTF_LABEL(finally, code, "PRNG implementation %s failed to export: %s",
				md->desc->name, error_to_string(err));
	}
	if (export_size_ul != (long unsigned int)md->desc->export_size)
		Tcl_SetByteArrayLength(res, md->desc->export_size);

	Tcl_SetObjResult(interp, res);

finally:
	replace_tclobj(&res, NULL);
	return code;
}

//>>>
#if TESTMODE
static int method_test(ClientData cdata, Tcl_Interp* interp, Tcl_ObjectContext context, int objc, Tcl_Obj*const objv[]) //<<<
{
	(void)cdata;
	int						code = TCL_OK;
	Tcl_Object				object = Tcl_ObjectContextObject(context);
	struct prng_md*			md = Tcl_ObjectGetMetadata(object, &prng_metadata);
	int						err;

	const int	A_cmd		= Tcl_ObjectContextSkippedArgs(context)-1;
	const int	A_objc		= A_cmd+1;
	CHECK_ARGS_LABEL(finally, code, "");

	if (CRYPT_OK != (err = md->desc->test())) {
		THROW_PRINTF_LABEL(finally, code, "PRNG implementation %s failed self test: %s",
				md->desc->name, error_to_string(err));
	}

finally:
	return code;
}

//>>>
#endif

#define OO_VER TCL_OO_METHOD_VERSION_CURRENT
static Tcl_MethodType methods[] = {
	{.name = NULL,			.callProc = ctor,				.version = OO_VER },
	{.name = "bytes",		.callProc = method_bytes,		.version = OO_VER },
	{.name = "add_entropy",	.callProc = method_add_entropy,	.version = OO_VER },
	{.name = "integer",		.callProc = method_integer,		.version = OO_VER },
	{.name = "double",		.callProc = method_double,		.version = OO_VER },
	{.name = "export",		.callProc = method_export,		.version = OO_VER },
#if TESTMODE
	{.name = "test",		.callProc = method_test,		.version = OO_VER },
#endif
	{0}
};
#undef OO_VER

int GetPrngFromObj(Tcl_Interp* interp, Tcl_Obj* prng, prng_state** state, int* desc_idx) //<<<
{
	int code = TCL_OK;

	Tcl_Object obj = Tcl_GetObjectFromObj(interp, prng);
	if (obj == NULL) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "VALUE", "PRNG", NULL);
		code = TCL_ERROR;
		goto finally;
	}

	struct prng_md* md = Tcl_ObjectGetMetadata(obj, &prng_metadata);
	if (md == NULL) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "VALUE", "PRNG", NULL);
		THROW_ERROR_LABEL(finally, code, "Not a prng instance");
	}

	*state = &md->prng;
	*desc_idx = md->desc_idx;

finally:
	return code;
}

//>>>
int prng_class_init(Tcl_Interp* interp, struct interp_cx* l) //<<<
{
	int				code = TCL_OK;
	Tcl_Class		cls;
	Tcl_Object		object;
	Tcl_Obj*		tmp = NULL;

	TEST_OK_LABEL(finally, code, Tcl_EvalObjEx(interp, l->lit[L_PRNG_CLASS_DEF], TCL_EVAL_GLOBAL));

	if (NULL == (object = Tcl_GetObjectFromObj(interp, l->lit[L_PRNG_CLASS]))) {
		code = TCL_ERROR;
		goto finally;
	}
	if (NULL == (cls = Tcl_GetObjectAsClass(object))) {
		code = TCL_ERROR;
		goto finally;
	}

	Tcl_ClassSetConstructor(interp, cls,
			Tcl_NewMethod(interp, cls, NULL, TCL_OO_METHOD_PUBLIC, &methods[0], l)
	);
	for (Tcl_MethodType* m = methods+1; m->name; m++) {
		replace_tclobj(&tmp, Tcl_NewStringObj(m->name, -1));
		Tcl_NewMethod(interp, cls, tmp, TCL_OO_METHOD_PUBLIC, m, l);
	}

finally:
	replace_tclobj(&tmp, NULL);
	return code;
}

//>>>

// vim: foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
