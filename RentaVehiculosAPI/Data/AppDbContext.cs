namespace RentaVehiculosAPI.Data
{
    using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
    using Microsoft.EntityFrameworkCore;
    using RentaVehiculosAPI.Models;

    public class AppDbContext : IdentityDbContext
    {
        public DbSet<Vehiculo> Vehiculos { get; set; }
        public DbSet<Reserva> Reservas { get; set; }
        public DbSet<AuditLog> AuditLogs { get; set; }

        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<Vehiculo>()
                .Property(v => v.TarifaPorHora)
                .HasColumnType("decimal(18,2)");

            modelBuilder.Entity<Vehiculo>()
                .Property(v => v.PenalizacionPorHora)
                .HasColumnType("decimal(18,2)");

            modelBuilder.Entity<Reserva>()
                .Property(r => r.CostoTotal)
                .HasColumnType("decimal(18,2)");

            // Configuración adicional (opcional)
        }
    }
}
