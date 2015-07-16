
extern int *a;

extern int doit(int *);

int func(int z)
{
	*a = z;
	return doit(a);
}
