using System;
namespace RentaVehiculosAPI.Models
{
    public class Reserva
    {
        public int ID { get; set; }
        public int VehiculoID { get; set; }
        public Vehiculo Vehiculo { get; set; } // Relación con la clase Vehiculo
        public string Cliente { get; set; }
        public DateTime FechaInicio { get; set; }
        public DateTime FechaFin { get; set; }
        public decimal CostoTotal { get; set; }
        public string Estado { get; set; } // Ejemplo: Confirmada, Finalizada, Cancelada
    }
}
