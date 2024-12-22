namespace RentaVehiculosAPI.Models
{
    public class Vehiculo
    {
        public int ID { get; set; }
        public string Marca { get; set; }
        public string Modelo { get; set; }
        public int Year { get; set; }
        public string Estado { get; set; } // Ejemplo: Disponible, Reservado, Mantenimiento
        public decimal TarifaPorHora { get; set; }
        public decimal PenalizacionPorHora { get; set; }
        public string Placa { get; set; } // Nueva propiedad opcional
        public string Color { get; set; } // Nueva propiedad opcional
        public int Asientos { get; set; } // Nueva propiedad opcional
        public byte[] Imagen { get; set; } // Propiedad para almacenar la imagen
    }

}
