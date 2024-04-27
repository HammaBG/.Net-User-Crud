using Microsoft.EntityFrameworkCore;

namespace Projet2.Models
{
    public class UserDbContext : DbContext
    {
        public UserDbContext(DbContextOptions options) : base(options) 
        {

        }
        public DbSet<User> User { get; set; }

    }
}
