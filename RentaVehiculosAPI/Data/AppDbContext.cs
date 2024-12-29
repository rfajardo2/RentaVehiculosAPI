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
        public DbSet<Cliente> Clientes { get; set; }


        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder); 


            //modelBuilder.Entity<Reserva>()
            //   .HasOne(r => r.Cliente)
            //   .WithMany(c => c.Reservas)
            //   .HasForeignKey(r => r.ClienteId)
            //   .OnDelete(DeleteBehavior.Restrict); // Evita eliminación en cascada si el cliente tiene reservas

            //modelBuilder.Entity<Reserva>()
            //    .HasOne(r => r.Vehiculo)
            //    .WithMany(v => v.Reservas)
            //    .HasForeignKey(r => r.VehiculoId)
            //    .OnDelete(DeleteBehavior.Restrict);
            //base.OnModelCreating(modelBuilder);



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
