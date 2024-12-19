namespace RentaVehiculosAPI.Models
{
    public class AuditLog
    {
        public int Id { get; set; }
        public string UserId { get; set; }
        public string Username { get; set; }
        public string Action { get; set; } // Por ejemplo: "CREATE", "UPDATE", "DELETE"
        public string Entity { get; set; } // Entidad afectada, por ejemplo: "User", "Reserva"
        public string Details { get; set; } // Información adicional
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }

}
