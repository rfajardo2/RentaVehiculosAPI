namespace RentaVehiculosAPI.Controllers
{
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    using RentaVehiculosAPI.Data;
    using RentaVehiculosAPI.Models;

    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class ReservasController : ControllerBase
    {
        private readonly AppDbContext _context;

        public ReservasController(AppDbContext context)
        {
            _context = context;
        }


        [Authorize]
        [HttpGet("protected")]
        public IActionResult ProtectedEndpoint()
        {
            return Ok("Este endpoint está protegido y solo accesible con un token válido.");
        }

        [Authorize(Roles = "Administrador")]
        [HttpGet("admin-only")]
        public IActionResult AdminOnlyEndpoint()
        {
            return Ok("Este endpoint es solo para administradores.");
        }

        [HttpGet]
        public IActionResult GetReservas()
        {
            var reservas = _context.Reservas.ToList();
            return Ok(reservas);
        }

        [HttpGet("{id}")]
        public IActionResult GetReserva(int id)
        {
            var reserva = _context.Reservas.Find(id);
            if (reserva == null) return NotFound();
            return Ok(reserva);
        }

        [HttpPost]
        public IActionResult CreateReserva([FromBody] Reserva reserva)
        {
            // Validar si el vehículo existe
            var vehiculo = _context.Vehiculos.Find(reserva.VehiculoID);
            if (vehiculo == null)
                return BadRequest("El vehículo seleccionado no existe.");

            // Buscar conflictos de fechas
            var conflicto = _context.Reservas
                .Where(r =>
                    r.VehiculoID == reserva.VehiculoID &&
                    r.Estado != "Cancelada" &&
                    ((reserva.FechaInicio >= r.FechaInicio && reserva.FechaInicio < r.FechaFin) ||
                     (reserva.FechaFin > r.FechaInicio && reserva.FechaFin <= r.FechaFin) ||
                     (reserva.FechaInicio <= r.FechaInicio && reserva.FechaFin >= r.FechaFin)))
                .Select(r => new { r.FechaInicio, r.FechaFin })
                .FirstOrDefault();

            if (conflicto != null)
                return BadRequest($"El vehículo no está disponible en el rango de fechas especificado. Conflicto con una reserva existente desde {conflicto.FechaInicio:yyyy-MM-dd HH:mm} hasta {conflicto.FechaFin:yyyy-MM-dd HH:mm}.");

            // Crear la reserva
            _context.Reservas.Add(reserva);
            _context.SaveChanges();

            return CreatedAtAction(nameof(GetReserva), new { id = reserva.ID }, reserva);
        }


        [HttpPut("{id}")]
        public IActionResult UpdateReserva(int id, [FromBody] Reserva reserva)
        {
            var existingReserva = _context.Reservas.Find(id);
            if (existingReserva == null)
                return NotFound();

            // Validar si el vehículo existe
            var vehiculo = _context.Vehiculos.Find(reserva.VehiculoID);
            if (vehiculo == null)
                return BadRequest("El vehículo seleccionado no existe.");

            // Buscar conflictos de fechas
            var conflicto = _context.Reservas
                .Where(r =>
                    r.VehiculoID == reserva.VehiculoID &&
                    r.ID != id &&
                    r.Estado != "Cancelada" &&
                    ((reserva.FechaInicio >= r.FechaInicio && reserva.FechaInicio < r.FechaFin) ||
                     (reserva.FechaFin > r.FechaInicio && reserva.FechaFin <= r.FechaFin) ||
                     (reserva.FechaInicio <= r.FechaInicio && reserva.FechaFin >= r.FechaFin)))
                .Select(r => new { r.FechaInicio, r.FechaFin })
                .FirstOrDefault();

            if (conflicto != null)
                return BadRequest($"El vehículo no está disponible en el rango de fechas especificado. Conflicto con una reserva existente desde {conflicto.FechaInicio:yyyy-MM-dd HH:mm} hasta {conflicto.FechaFin:yyyy-MM-dd HH:mm}.");

            // Actualizar la reserva
            existingReserva.VehiculoID = reserva.VehiculoID;
            existingReserva.Cliente = reserva.Cliente;
            existingReserva.FechaInicio = reserva.FechaInicio;
            existingReserva.FechaFin = reserva.FechaFin;
            existingReserva.CostoTotal = reserva.CostoTotal;
            existingReserva.Estado = reserva.Estado;

            _context.SaveChanges();
            return NoContent();
        }


        [HttpDelete("{id}")]
        public IActionResult DeleteReserva(int id)
        {
            var reserva = _context.Reservas.Find(id);
            if (reserva == null) return NotFound();

            _context.Reservas.Remove(reserva);
            _context.SaveChanges();
            return NoContent();
        }
    }

}
