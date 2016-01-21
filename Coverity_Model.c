void cn_cbor_free(void  *cb) {
    __coverity_free__(cb);
}

void * cn_cbor_map_create(void * context, void * errp)
{
    __coverity_alloc__(10);
}

void * cn_cbor_data_create(const char * data, int len, void * context, void * errp)
{
    __coverity_alloc__(10);
    __coverity_escape__(data);
}

void * cn_cbor_string_create(const char * data, void * context, void * errp)
{
    __coverity_alloc__(10);
    __coverity_escape__(data);
}

void * cn_cbor_array_create(void * context, void * errp)
{
    __coverity_alloc__(10);
}

void * cn_cbor_decode(const char * pbuf, size_t len, void * context, void * errp)
{
    __coverity_alloc__(len);
    __coverity_escape__(pbuf);
}
