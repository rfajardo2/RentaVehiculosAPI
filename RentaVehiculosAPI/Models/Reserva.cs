using System;
using System.ComponentModel.DataAnnotations;
namespace RentaVehiculosAPI.Models
{
    public class Reserva
    {
        public int Id { get; set; }

        public int ClienteId { get; set; }

        public int VehiculoId { get; set; }

        public DateTime FechaReserva { get; set; }

        public DateTime FechaInicio { get; set; }
        public DateTime FechaFin { get; set; }

        public string Estado { get; set; }

        public string LugarRecogida { get; set; }
        public string LugarDevolucion { get; set; }

        public decimal CostoTotal { get; set; }
        public decimal Costo { get; set; }
        public decimal Penalizacion { get; set; }
        public DateTime? FechaFinReal { get; set; }
    }



}
