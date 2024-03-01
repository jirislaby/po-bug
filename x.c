void put(unsigned short val, void *p)
{
	struct {
		unsigned short x;
	} *pp = p;
	pp->x = val;
}
