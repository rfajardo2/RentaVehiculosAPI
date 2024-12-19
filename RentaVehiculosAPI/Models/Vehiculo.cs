namespace RentaVehiculosAPI.Models
{
    public class Vehiculo
    {
        public int ID { get; set; }
        public string Marca { get; set; }
        public string Modelo { get; set; }
        public int Año { get; set; }
        public string Estado { get; set; } // Ejemplo: Disponible, Reservado, Mantenimiento
        public decimal TarifaPorHora { get; set; }
        public decimal PenalizacionPorHora { get; set; }
    }
}
