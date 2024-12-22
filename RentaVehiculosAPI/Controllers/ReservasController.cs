namespace RentaVehiculosAPI.Controllers
{
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.EntityFrameworkCore;
    using RentaVehiculosAPI.Data;
    using RentaVehiculosAPI.Models;

    [Authorize] // Requiere autenticación para todas las acciones
    [ApiController]
    [Route("api/[controller]")]
    public class ReservasController : ControllerBase
    {
        private readonly AppDbContext _context;

        public ReservasController(AppDbContext context)
        {
            _context = context;
        }

        // Obtener todas las reservas
        [HttpGet]
        public async Task<IActionResult> GetReservas()
        {
            var reservas = await _context.Reservas
                .Include(r => r.Cliente)
                .Include(r => r.Vehiculo)
                .ToListAsync();

            return Ok(reservas.Select(r => new
            {
                r.Id,
                Cliente = r.Cliente.Nombre,
                Vehiculo = $"{r.Vehiculo.Marca} {r.Vehiculo.Modelo}",
                r.FechaRecogida,
                r.FechaDevolucion,
                r.LugarRecogida,
                r.LugarDevolucion,
                r.CostoTotal,
                r.Estado
            }));
        }

        // Obtener una reserva por ID
        [HttpGet("{id}")]
        public async Task<IActionResult> GetReserva(int id)
        {
            var reserva = await _context.Reservas
                .Include(r => r.Cliente)
                .Include(r => r.Vehiculo)
                .FirstOrDefaultAsync(r => r.Id == id);

            if (reserva == null)
                return NotFound(new { message = "Reserva no encontrada" });

            return Ok(reserva);
        }

        // Crear una nueva reserva
        [HttpPost]
        public async Task<IActionResult> CrearReserva([FromBody] Reserva reserva)
        {
            var vehiculo = await _context.Vehiculos.FindAsync(reserva.VehiculoId);
            if (vehiculo == null)
                return NotFound(new { message = "Vehículo no encontrado" });

            if (vehiculo.Estado != "Disponible")
                return BadRequest(new { message = "El vehículo no está disponible para reservar" });

            reserva.Estado = "Activa";
            _context.Reservas.Add(reserva);

            vehiculo.Estado = "Reservado"; // Cambiar el estado del vehículo
            await _context.SaveChangesAsync();

            return Ok(new { message = "Reserva creada exitosamente" });
        }

        // Actualizar una reserva existente
        [HttpPut("{id}")]
        public async Task<IActionResult> ActualizarReserva(int id, [FromBody] Reserva reserva)
        {
            var reservaExistente = await _context.Reservas.FindAsync(id);
            if (reservaExistente == null)
                return NotFound(new { message = "Reserva no encontrada" });

            reservaExistente.FechaRecogida = reserva.FechaRecogida;
            reservaExistente.FechaDevolucion = reserva.FechaDevolucion;
            reservaExistente.LugarRecogida = reserva.LugarRecogida;
            reservaExistente.LugarDevolucion = reserva.LugarDevolucion;
            reservaExistente.CostoTotal = reserva.CostoTotal;

            await _context.SaveChangesAsync();
            return Ok(new { message = "Reserva actualizada exitosamente" });
        }

        // Cancelar una reserva
        [HttpPut("cancelar/{id}")]
        public async Task<IActionResult> CancelarReserva(int id)
        {
            var reserva = await _context.Reservas.FindAsync(id);
            if (reserva == null)
                return NotFound(new { message = "Reserva no encontrada" });

            if (reserva.Estado != "Activa")
                return BadRequest(new { message = "Solo se pueden cancelar reservas activas" });

            reserva.Estado = "Cancelada";

            var vehiculo = await _context.Vehiculos.FindAsync(reserva.VehiculoId);
            if (vehiculo != null)
                vehiculo.Estado = "Disponible"; // Liberar el vehículo

            await _context.SaveChangesAsync();
            return Ok(new { message = "Reserva cancelada exitosamente" });
        }

        // Finalizar una reserva (Devolución de vehículo)
        [HttpPut("finalizar/{id}")]
        public async Task<IActionResult> FinalizarReserva(int id)
        {
            var reserva = await _context.Reservas.FindAsync(id);
            if (reserva == null)
                return NotFound(new { message = "Reserva no encontrada" });

            if (reserva.Estado != "Activa")
                return BadRequest(new { message = "Solo se pueden finalizar reservas activas" });

            reserva.Estado = "Completada";

            var vehiculo = await _context.Vehiculos.FindAsync(reserva.VehiculoId);
            if (vehiculo != null)
                vehiculo.Estado = "Disponible"; // Liberar el vehículo

            await _context.SaveChangesAsync();
            return Ok(new { message = "Reserva finalizada exitosamente" });
        }

        // Eliminar una reserva
        [HttpDelete("{id}")]
        public async Task<IActionResult> EliminarReserva(int id)
        {
            var reserva = await _context.Reservas.FindAsync(id);
            if (reserva == null)
                return NotFound(new { message = "Reserva no encontrada" });

            _context.Reservas.Remove(reserva);
            await _context.SaveChangesAsync();
            return Ok(new { message = "Reserva eliminada exitosamente" });
        }
    }






    public class CrearReservaDto
    {
        public int ClienteId { get; set; }
        public int VehiculoId { get; set; }
        public DateTime FechaRecogida { get; set; }
        public DateTime FechaDevolucion { get; set; }
        public string LugarRecogida { get; set; }
        public string LugarDevolucion { get; set; }
        public decimal CostoTotal { get; set; }
    }
    public class ActualizarReservaDto : CrearReservaDto
    {
    }


}
