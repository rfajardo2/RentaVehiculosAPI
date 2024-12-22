using System;
namespace RentaVehiculosAPI.Models
{
    public class Reserva
    {
        public int Id { get; set; } // Identificador único de la reserva

        // Relación con Cliente
        public int ClienteId { get; set; }
        public Cliente Cliente { get; set; } // Referencia al modelo Cliente

        // Relación con Vehículo
        public int VehiculoId { get; set; }
        public Vehiculo Vehiculo { get; set; } // Referencia al modelo Vehículo

        public DateTime FechaRecogida { get; set; } // Fecha y hora de recogida del vehículo
        public DateTime FechaDevolucion { get; set; } // Fecha y hora de devolución del vehículo
        public string LugarRecogida { get; set; } // Lugar de recogida del vehículo
        public string LugarDevolucion { get; set; } // Lugar de devolución del vehículo
        public decimal CostoTotal { get; set; } // Costo total de la renta
        public string Estado { get; set; } // Estado de la reserva: "Activa", "Cancelada", "Completada"
    }

}
