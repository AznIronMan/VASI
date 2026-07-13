export const validateBootstrapInputs = ({ email, name, password }) => {
  const normalizedEmail = String(email || '')
    .trim()
    .toLowerCase();
  const normalizedName = String(name || '').trim();
  const normalizedPassword = String(password || '');

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
    throw new Error('VASI_BOOTSTRAP_ADMIN_EMAIL must be a valid email address');
  }

  if (normalizedName.length < 3 || normalizedName.length > 255 || /https?:\/\/|www\./i.test(normalizedName)) {
    throw new Error('VASI_BOOTSTRAP_ADMIN_NAME must be 3-255 characters and must not contain a URL');
  }

  if (normalizedPassword.length < 16 || normalizedPassword.length > 256) {
    throw new Error('The bootstrap password must be 16-256 characters');
  }

  return { email: normalizedEmail, name: normalizedName, password: normalizedPassword };
};

export const bootstrapInitialAdmin = async ({ prisma, hashPassword, email, name, password }) => {
  const existingAdminCount = await prisma.user.count({
    where: { roles: { has: 'ADMIN' } },
  });

  if (existingAdminCount > 0) {
    throw new Error('An administrator already exists; bootstrap mode refuses to create another');
  }

  const existingUser = await prisma.user.findUnique({ where: { email } });
  if (existingUser) {
    throw new Error('The bootstrap email already exists; bootstrap mode will not modify an existing user');
  }

  const passwordHash = await hashPassword(password);
  return await prisma.user.create({
    data: {
      name,
      email,
      emailVerified: new Date(),
      password: passwordHash,
      roles: ['USER', 'ADMIN'],
      source: 'VASI_BOOTSTRAP',
    },
    select: { id: true },
  });
};
