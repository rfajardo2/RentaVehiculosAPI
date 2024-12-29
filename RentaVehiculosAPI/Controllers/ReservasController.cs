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
            var reservas = await _context.Reservas.ToListAsync();
            List<GetReservasDto> ListgetReservasDtos = new List<GetReservasDto>(); 

            foreach (var reservation in reservas)
            {
                GetReservasDto getReservasDto = new GetReservasDto();
                getReservasDto.Reserva = reservation;
                getReservasDto.cliente = await _context.Clientes.Where(w=> w.ID==reservation.ClienteId).FirstOrDefaultAsync();
                getReservasDto.vehiculo = await _context.Vehiculos.Where(w => w.ID == reservation.VehiculoId).FirstOrDefaultAsync();
                ListgetReservasDtos.Add(getReservasDto);
            }

            return Ok(ListgetReservasDtos);
        }

        // Obtener una reserva por ID
        [HttpGet("{id}")]
        public async Task<IActionResult> GetReserva(int id)
        {
            GetReservasDto getReservasDto = new GetReservasDto();
            var reserva = await _context.Reservas
                .FirstOrDefaultAsync(r => r.Id == id);

            if (reserva == null)
                return NotFound(new { message = "Reserva no encontrada" });

            getReservasDto.Reserva = reserva;
            getReservasDto.cliente = await _context.Clientes.Where(w => w.ID == reserva.ClienteId).FirstOrDefaultAsync();
            getReservasDto.vehiculo = await _context.Vehiculos.Where(w => w.ID == reserva.VehiculoId).FirstOrDefaultAsync();

            return Ok(reserva);
        }

        // Crear una nueva reserva
        [HttpPost]
        public async Task<IActionResult> CrearReserva([FromBody] CrearReservaDto reserva_)
        {
            Reserva reserva = new Reserva();
            reserva.ClienteId = reserva_.ClienteId;
            reserva.VehiculoId = reserva_.VehiculoId;

            reserva.FechaInicio = reserva_.FechaInicio.Date;
            reserva.FechaFin = reserva_.FechaFin.Date;
            TimeSpan horaInicioTimeSpan = TimeSpan.Parse(reserva_.horaInicio);
            TimeSpan horaFinTimeSpan = TimeSpan.Parse(reserva_.horaFin);

            reserva.FechaInicio = reserva.FechaInicio.Add(horaInicioTimeSpan);
            reserva.FechaFin = reserva.FechaInicio.Add(horaFinTimeSpan);



            reserva.LugarRecogida = reserva_.LugarRecogida;
            reserva.LugarDevolucion = reserva_.LugarDevolucion;
            reserva.CostoTotal = reserva_.CostoTotal;
            reserva.Penalizacion = reserva_.Penalizacion;
            reserva.Costo = reserva_.Costo;
            reserva.FechaFinReal = reserva_.FechaFinReal;




            var vehiculo = await _context.Vehiculos.FindAsync(reserva.VehiculoId);

            if (vehiculo == null)
                return NotFound(new { message = "Vehículo no encontrado" });

            if (vehiculo.Estado != "Disponible")
                return BadRequest(new { message = "El vehículo no está disponible para reservar" });

            reserva.Estado = "Activa";
            reserva.FechaReserva = DateTime.Now;
            _context.Reservas.Add(reserva);

            vehiculo.Estado = "Reservado"; // Cambiar el estado del vehículo
            _context.Entry(vehiculo).State = EntityState.Modified;

            await _context.SaveChangesAsync();

            return Ok(new { message = "Reserva creada exitosamente" });
        }

        // Actualizar una reserva existente
        [HttpPut("{id}")]
        public async Task<IActionResult> ActualizarReserva(int id, [FromBody] CrearReservaDto reserva)
        {
            var reservaExistente = await _context.Reservas.FindAsync(id);
            if (reservaExistente == null)
                return NotFound(new { message = "Reserva no encontrada" });

            
            reservaExistente.LugarRecogida = reserva.LugarRecogida;
            reservaExistente.LugarDevolucion = reserva.LugarDevolucion;

            reserva.FechaInicio = reserva.FechaInicio.Date;
            reserva.FechaFin = reserva.FechaFin.Date;
            TimeSpan horaInicioTimeSpan = TimeSpan.Parse(reserva.horaInicio);
            TimeSpan horaFinTimeSpan = TimeSpan.Parse(reserva.horaFin);

            reserva.FechaInicio = reserva.FechaInicio.Add(horaInicioTimeSpan);
            reserva.FechaFin = reserva.FechaInicio.Add(horaFinTimeSpan);



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

            _context.Entry(vehiculo).State = EntityState.Modified;

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




    public class GetReservasDto
    {
        public Reserva Reserva { get; set; }
        public Cliente cliente { get; set; }
        public Vehiculo vehiculo { get; set; }
    }

    public class CrearReservaDto
    {

        public int ClienteId { get; set; }
        public int VehiculoId { get; set; }
        public DateTime FechaReserva { get; set; }
        public DateTime FechaInicio { get; set; }
        public DateTime FechaFin { get; set; }
        public string Estado { get; set; }
        public string LugarRecogida { get; set; }
        public string LugarDevolucion { get; set; }
        public decimal CostoTotal { get; set; }
        public string horaInicio { get; set; }
        public string horaFin { get; set; }
        public decimal Costo { get; set; }
        public decimal Penalizacion { get; set; }
        public DateTime? FechaFinReal { get; set; }
    }
    public class ActualizarReservaDto : CrearReservaDto
    {
    }


}
