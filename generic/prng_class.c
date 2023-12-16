#include "tomcryptInt.h"

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
static int clone_prng_state(Tcl_Interp*, void* cdata, void** new_cdata) //<<<
{
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

	int			type_len;
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
		int				entropy_len = 0;
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
		THROW_PRINTF_LABEL(finally, code, "count cannot be negative");
	}

	if (count == 0) {
		Tcl_SetObjResult(interp, l->lit[L_NOBYTES]);
		goto finally;
	}

	int					buflen = count;
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
	int						code = TCL_OK;
	Tcl_Object				object = Tcl_ObjectContextObject(context);
	struct prng_md*			md = Tcl_ObjectGetMetadata(object, &prng_metadata);
	int						err;

	const int	A_cmd		= Tcl_ObjectContextSkippedArgs(context)-1;
	const int	A_ENTROPY	= A_cmd+1;
	const int	A_objc		= A_cmd+2;
	CHECK_ARGS_LABEL(finally, code, "entropy");

	int				entropy_len = 0;
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

	int		lower_type, upper_type;
	void	*lower_info = NULL, *upper_info = NULL;
	TEST_OK_LABEL(finally, code, Tcl_GetNumberFromObj(interp, objv[A_LOWER], &lower_info, &lower_type));
	TEST_OK_LABEL(finally, code, Tcl_GetNumberFromObj(interp, objv[A_UPPER], &upper_info, &upper_type));

	switch (lower_type) {
		case TCL_NUMBER_INT: case TCL_NUMBER_BIG: break;
		default:
			Tcl_SetErrorCode(interp, "TCL", "VALUE", "NUMBER", NULL);
			THROW_PRINTF_LABEL(finally, code, "expected integer but got \"%s\"", Tcl_GetString(objv[A_LOWER]));
	}
	switch (upper_type) {
		case TCL_NUMBER_INT: case TCL_NUMBER_BIG: break;
		default:
			Tcl_SetErrorCode(interp, "TCL", "VALUE", "NUMBER", NULL);
			THROW_PRINTF_LABEL(finally, code, "expected integer but got \"%s\"", Tcl_GetString(objv[A_UPPER]));
	}

	if (
			lower_type == TCL_NUMBER_INT &&
			upper_type == TCL_NUMBER_INT
	) {
		const Tcl_WideInt		lower_val = *(Tcl_WideInt*)lower_info;
		const Tcl_WideInt		upper_val = *(Tcl_WideInt*)upper_info;

		if (lower_val > upper_val) {
			Tcl_SetErrorCode(interp, "TOMCRYPT", "VALUE", NULL);
			THROW_ERROR_LABEL(finally, code, "lower must be less than or equal to upper")
		}

		const Tcl_WideUInt		range = upper_val - lower_val;

		if (range == 0) {
			// Shrug.  I guess it's still random and uniform in given the
			// range.  Sure, here's your random constant
			Tcl_SetObjResult(interp, objv[A_LOWER]);
			goto finally;
		}

		const int		range_bitlen = (int)log2(range);
		const int		range_bytelen = (range_bitlen+7)/8;
		Tcl_WideUInt	range_mask = (1<<(range_bitlen+1))-1;
		uint8_t			buf[range_bytelen];

		// To enforce uniform (unbiased) distribution, we need to keep rolling
		// until a masked value is in range, worst case should be a 50% chance per roll
		for (int i=0; i<100; i++) {
			const unsigned long got = md->desc->read(buf, range_bytelen, &md->prng);
			if (got != range_bytelen) {
				Tcl_SetErrorCode(interp, "TOMCRYPT", "PRNG", "READ", NULL);
				THROW_PRINTF_LABEL(finally, code, "PRNG implementation %s failed to read %d bytes",
						md->desc->name, range_bytelen);
			}
			const Tcl_WideUInt value = *(Tcl_WideUInt*)buf & range_mask;
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
		// At least one of the values is a bignum
		int			rc;
		mp_int		lower_bigval = {0};
		mp_int		upper_bigval = {0};
		mp_int		range_bigval = {0};
		mp_int		value_bigval = {0};
		uint32_t	range_bitlen_bigval;
		uint32_t	range_bytelen_bigval;
		uint32_t	range_remain_bigval;
		if (MP_OKAY != (rc = mp_init_multi(/*&range_bigval,*/ &value_bigval, NULL)))		goto mp_err;
#if DEBUG
		fprintf(stderr, "mp_init_multi(&range_bigval.dp: %p, &value_bigval.dp: %p, NULL)\n", range_bigval.dp, value_bigval.dp);
#endif

		TEST_OK_LABEL(mp_finally, code, Tcl_GetBignumFromObj(interp, objv[A_LOWER], &lower_bigval));
		TEST_OK_LABEL(mp_finally, code, Tcl_GetBignumFromObj(interp, objv[A_UPPER], &upper_bigval));

		if (MP_OKAY != (rc = mp_init(&range_bigval)))									goto mp_err;
		switch (mp_cmp_mag(&lower_bigval, &upper_bigval)) {
			case MP_GT:
				Tcl_SetErrorCode(interp, "TOMCRYPT", "VALUE", NULL);
				THROW_ERROR_LABEL(mp_finally, code, "lower must be less than or equal to upper")
			case MP_EQ:
				// Shrug.  I guess it's still random and uniform in given the
				// range.  Sure, here's your random constant
				Tcl_SetObjResult(interp, objv[A_LOWER]);
				goto mp_finally;
		}
		if (MP_OKAY != (rc = mp_sub(&upper_bigval, &lower_bigval, &range_bigval)))		goto mp_err;
		//if (MP_OKAY != (rc = mp_log_u32(&range_bigval, 2, &range_bitlen_bigval)))		goto mp_err;
		range_bitlen_bigval  = mp_count_bits(&range_bigval);
		range_bytelen_bigval = (range_bitlen_bigval+7)/8;
		range_remain_bigval  = range_bitlen_bigval % 8;
		uint8_t	topbyte_mask = range_remain_bigval ? (1<<range_remain_bigval)-1 : 0xff;
#if DEBUG
		fprintf(stderr, "range_bigval: 0x");
		if (MP_OKAY != (rc = mp_fwrite(&range_bigval, 16, stderr)))						goto mp_err;
		fprintf(stderr, "\n");
		fprintf(stderr, "range_bitlen_bigval: %d, range_bytelen_bigval: %d, range_remain_bigval: %d, topbyte_mask: 0x%1x\n", range_bitlen_bigval, range_bytelen_bigval, range_remain_bigval, topbyte_mask);
#endif

		// To enforce uniform (unbiased) distribution, we need to keep rolling
		// until a masked value is in range, worst case should be a 50% chance per roll
		for (int i=0; i<100; i++) {
			uint8_t		buf_bigval[range_bytelen_bigval];
			const unsigned long got = md->desc->read(buf_bigval, range_bytelen_bigval, &md->prng);
			if (got != range_bytelen_bigval) {
				Tcl_SetErrorCode(interp, "TOMCRYPT", "PRNG", "READ", NULL);
				THROW_PRINTF_LABEL(mp_finally, code, "PRNG implementation %s failed to read %d bytes",
						md->desc->name, range_bytelen_bigval);
			}
			buf_bigval[0] &= topbyte_mask;
#if DEBUG
			fprintf(stderr, "got: %ld, buf_bigval[0]: 0x%02X\n", got, buf_bigval[0]);
#endif
			if (MP_OKAY != (rc = mp_from_ubin(&value_bigval, buf_bigval, range_bytelen_bigval)))	goto mp_err;
			if (MP_GT == mp_cmp_mag(&value_bigval, &range_bigval)) {
#if DEBUG
				fprintf(stderr, "%3d: rolled bytes: %ld, range: 0x", i, got);
				if (MP_OKAY != (rc = mp_fwrite(&range_bigval, 16, stderr)))							goto mp_err;
				fprintf(stderr, ", value: 0x");
				if (MP_OKAY != (rc = mp_fwrite(&value_bigval, 16, stderr)))							goto mp_err;
				fprintf(stderr, ", range_bitlen: %d, range_bytelen: %d, range_mask: 0x%02X\n", range_bitlen_bigval, range_bytelen_bigval, topbyte_mask);
#endif
				continue;
			}
			if (MP_OKAY != (rc = mp_add(&lower_bigval, &value_bigval, &value_bigval)))				goto mp_err;
#if 0
			// Tcl_NewBignumObj takes ownership of the memory in the mp_int passed, which eventually
			// means it tries to free it with ckalloc, but value_bigval was allocated by the external
			// libtommath mp_init, and hence malloc.  This does not end well so we have to hack around
			// it by making a manual copy, with storage allocated by ckalloc
			mp_int		value_bigval_copy = value_bigval;
			value_bigval_copy.dp = ckalloc(value_bigval_copy.alloc * sizeof(mp_digit));
			memcpy(value_bigval_copy.dp, value_bigval.dp, value_bigval_copy.alloc * sizeof(mp_digit));
#if DEBUG
			fprintf(stderr, "before, value_bigval.dp: %p, value_bigval_copy.dp: %p\n", value_bigval.dp, value_bigval_copy.dp);
#endif
			Tcl_SetObjResult(interp, Tcl_NewBignumObj(&value_bigval_copy));
#if DEBUG
			fprintf(stderr, "after,  value_bigval.dp: %p, value_bigval_copy.dp: %p\n", value_bigval.dp, value_bigval_copy.dp);
#endif
#else
			// Tcl_NewBignumObj takes ownership of the memory in the mp_int passed, which eventually
			// means it tries to free it with ckalloc, but value_bigval was allocated by the external
			// libtommath mp_init, and hence malloc.  This does not end well so we have to hack around
			// it by constructing a hex string rep and using Tcl_ExprObj to convert it to a bignum
#if DEBUG
			fprintf(stderr, "mp_fwrite: 0x");
			if (MP_OKAY != (rc = mp_fwrite(&value_bigval, 16, stderr)))						goto mp_err;
#endif
			const size_t	need = ((mp_count_bits(&value_bigval)+3)/4)+1;	// +1: \0
#if DEBUG
			fprintf(stderr, "\nComputed need: %zd\n", need);
#endif
			char			hexrep[2+need];									// +2: 0x
			hexrep[0] = '0';
			hexrep[1] = 'x';
			size_t			wrote = 0;
			if (MP_OKAY != (rc = mp_to_radix(&value_bigval, hexrep+2, need+1, &wrote, 16)))			goto mp_err;
			if (wrote != need) {
#if DEBUG
				fprintf(stderr, "   manual: %s\n", hexrep);
#endif
				THROW_PRINTF_LABEL(mp_finally, code, "Expecting to write %zd bytes, but wrote %zd", need, wrote);
			}
			replace_tclobj(&tmp, Tcl_NewStringObj(hexrep, 2+need-1));	// -1: \0
			replace_tclobj(&res, NULL);	// Make sure res doesn't point to an obj, Tcl_ExprObj may set it
#if DEBUG
			fprintf(stderr, "Using expr hack on (%s)\n", Tcl_GetString(tmp));
#endif
			TEST_OK_LABEL(mp_finally, code, Tcl_ExprObj(interp, tmp, &res));	// we own the ref in res if ExprObj sets it
			Tcl_SetObjResult(interp, res);
#endif
			goto mp_finally;
		}

		// Circuit breaker - if we haven't rolled a value in range after 100
		// tries (at most a 1/2**100 chance), then the prng is almost certainly faulty
		THROW_PRINTF_LABEL(mp_finally, code, "PRNG implementation %s failed to generate a value in range after 100 tries", md->desc->name);
		// TODO: implement mp_read_unsigned_bin

mp_finally:
#if DEBUG
		fprintf(stderr, "mp_clear_multi(&range_bigval (dp: %p), &value_bigval (dp: %p), NULL)\n", range_bigval.dp, value_bigval.dp);
#endif
		mp_clear_multi(&range_bigval, &value_bigval, NULL);
#if 1
		if (lower_bigval.dp) {
			ckfree(lower_bigval.dp);
			lower_bigval = (mp_int){0};
		}
		if (upper_bigval.dp) {
			ckfree(upper_bigval.dp);
			upper_bigval = (mp_int){0};
		}
#endif
		goto finally;

mp_err:
		THROW_PRINTF_LABEL(mp_finally, code, "failed to initialize bignum: %s", mp_error_to_string(rc));
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
	int						code = TCL_OK;
	Tcl_Object				object = Tcl_ObjectContextObject(context);
	struct prng_md*			md = Tcl_ObjectGetMetadata(object, &prng_metadata);

	const int	A_cmd		= Tcl_ObjectContextSkippedArgs(context)-1;
	const int	A_objc		= A_cmd+1;
	CHECK_ARGS_LABEL(finally, code);

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

	unsigned long	export_size = md->desc->export_size;
	replace_tclobj(&res, Tcl_NewByteArrayObj(NULL, export_size));
	uint8_t*		export = Tcl_GetBytesFromObj(interp, res, NULL);
	if (export == NULL) { code = TCL_ERROR; goto finally; }
	if (CRYPT_OK != (err = md->desc->pexport(export, &export_size, &md->prng))) {
		THROW_PRINTF_LABEL(finally, code, "PRNG implementation %s failed to export: %s",
				md->desc->name, error_to_string(err));
	}
	if (export_size != md->desc->export_size)
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
