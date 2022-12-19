


namespace VerifyEmailForgotResetPasswordApp.Database
{
    public class Context:DbContext
    {
        public Context(DbContextOptions<Context> options):base(options) { }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            base.OnConfiguring(optionsBuilder);
            optionsBuilder.UseSqlServer("Server=SAHINBEKIR\\SQLExpress01;Database=userdb;integrated security=true;");
        }

        public DbSet<User> Users => Set<User>();
    }
}
